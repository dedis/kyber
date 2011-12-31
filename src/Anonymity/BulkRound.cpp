#include "../Connections/Connection.hpp"
#include "../Connections/Network.hpp"
#include "../Crypto/DiffieHellman.hpp"
#include "../Crypto/Hash.hpp"
#include "../Crypto/Library.hpp"
#include "../Messaging/RpcRequest.hpp"
#include "../Utils/QRunTimeError.hpp"
#include "../Utils/Random.hpp"
#include "../Utils/Serialization.hpp"

#include "BulkRound.hpp"
#include "ShuffleRound.hpp"

using Dissent::Connections::Connection;
using Dissent::Crypto::CryptoFactory;
using Dissent::Crypto::DiffieHellman;
using Dissent::Crypto::Hash;
using Dissent::Crypto::Library;
using Dissent::Messaging::RpcRequest;
using Dissent::Utils::QRunTimeError;
using Dissent::Utils::Random;
using Dissent::Utils::Serialization;

namespace Dissent {
namespace Anonymity {
  BulkRound::BulkRound(const Group &group, const Credentials &creds,
      const Id &round_id, QSharedPointer<Network> network,
      GetDataCallback &get_data, CreateRound create_shuffle) :
    Round(group, creds, round_id, network, get_data),
    _my_idx(-1),
    _create_shuffle(create_shuffle),
    _get_bulk_data(this, &BulkRound::GetBulkData),
    _get_blame_data(this, &BulkRound::GetBlameData),
    _state(Offline),
    _messages(GetGroup().Count()),
    _received_messages(0)
  {
    QVariantMap headers = GetNetwork()->GetHeaders();
    headers["bulk"] = true;
    GetNetwork()->SetHeaders(headers);

    DiffieHellman *dh = CryptoFactory::GetInstance().GetLibrary()->CreateDiffieHellman();
    _anon_dh = QSharedPointer<DiffieHellman>(dh);

    QSharedPointer<Network> net(GetNetwork()->Clone());
    headers["bulk"] = false;
    net->SetHeaders(headers);

    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QScopedPointer<Hash> hashalgo(lib->GetHashAlgorithm());
    Id sr_id(hashalgo->ComputeHash(GetRoundId().GetByteArray()));

    Round *pr = _create_shuffle(GetGroup(), GetCredentials(), sr_id, net,
        _get_bulk_data);
    _shuffle_round = QSharedPointer<Round>(pr);

    _shuffle_round->SetSink(&_shuffle_sink);

    QObject::connect(_shuffle_round.data(), SIGNAL(Finished()),
        this, SLOT(ShuffleFinished()));
  }

  void Xor(QByteArray &dst, const QByteArray &t1, const QByteArray &t2)
  {
    /// @todo use qint64 or qint32 depending on architecture
    int count = std::min(dst.size(), t1.size());
    count = std::min(count, t2.size());

    for(int idx = 0; idx < count; idx++) {
      dst[idx] = t1[idx] ^ t2[idx];
    }
  }

  bool BulkRound::Start()
  {
    if(!Round::Start()) {
      return false;
    }

    _state = Shuffling;
    _shuffle_round->Start();

    return true;
  }

  void BulkRound::IncomingData(RpcRequest &notification)
  {
    if(Stopped()) {
      qWarning() << "Received a message on a closed session:" << ToString();
      return;
    }
      
    Dissent::Messaging::ISender *from = notification.GetFrom();
    Connection *con = dynamic_cast<Connection *>(from);
    const Id &id = con->GetRemoteId();
    if(con == 0 || !GetGroup().Contains(id)) {
      qDebug() << ToString() << " received wayward message from: " << from->ToString();
      return;
    }

    bool bulk = notification.GetMessage()["bulk"].toBool();
    if(bulk) {
      ProcessData(notification.GetMessage()["data"].toByteArray(), id);
    } else {
      _shuffle_round->IncomingData(notification);
    }
  }

  void BulkRound::ProcessData(const QByteArray &data, const Id &from)
  {
    _log.Append(data, from);
    try {
      ProcessDataBase(data, from);
    } catch (QRunTimeError &err) {
      qWarning() << GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
        "received a message from" << GetGroup().GetIndex(from) << from.ToString() <<
        "in session / round" << GetRoundId().ToString() << "in state" <<
        StateToString(_state) << "causing the following exception: " << err.What();
      _log.Pop();
      return;
    }
  }

  void BulkRound::ProcessDataBase(const QByteArray &data, const Id &from)
  {
    QByteArray payload;
    if(!Verify(data, payload, from)) {
      throw QRunTimeError("Invalid signature or data");
    }

    if(_state == Offline) {
      throw QRunTimeError("Should never receive a message in the bulk"
          " round while offline.");
    }

    QDataStream stream(payload);

    int mtype;
    QByteArray round_id;
    stream >> mtype >> round_id;

    MessageType msg_type = (MessageType) mtype;

    Id rid(round_id);
    if(rid != GetRoundId()) {
      throw QRunTimeError("Not this round: " + rid.ToString() + " " +
          GetRoundId().ToString());
    }

    if(_state == Shuffling) {
      _log.Pop();
      _offline_log.Append(data, from);
      return;
    }

    switch(msg_type) {
      case BulkData:
        HandleBulkData(stream, from);
        break;
      default:
        throw QRunTimeError("Unknown message type");
    }
  }

  void BulkRound::HandleBulkData(QDataStream &stream, const Id &from)
  {
    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
      ": received bulk data from " << GetGroup().GetIndex(from) << from.ToString();

    if(_state != DataSharing) {
      throw QRunTimeError("Received a misordered BulkData message");
    }

    int idx = GetGroup().GetIndex(from);
    if(!_messages[idx].isEmpty()) {
      throw QRunTimeError("Already have bulk data.");
    }

    QByteArray payload;
    stream >> payload;

    if(payload.size() != _expected_bulk_size) {
      throw QRunTimeError("Incorrect bulk message length");
    }

    _messages[idx] = payload;

    if(++_received_messages == GetGroup().Count()) {
      ProcessMessages();

      if(_bad_message_hash.isEmpty()) {
        _state = Finished;
        SetSuccessful(true);
        Stop("Round successfully finished");
      } else {
        BeginBlame();
      }
    }
  }

  void BulkRound::ProcessMessages()
  {
    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QScopedPointer<Hash> hashalgo(lib->GetHashAlgorithm());
    int size = _descriptors.size();
    int index = 0;

    for(int idx = 0; idx < size; idx++) {
      QByteArray cleartext = ProcessMessage(idx, index);
      if(!cleartext.isEmpty()) {
        PushData(cleartext, this);
      }
      index += _descriptors[idx].first;
    }
  }

  QByteArray BulkRound::ProcessMessage(int des_idx, int msg_index)
  {
    int count = _messages.size();
    const Descriptor &des = GetDescriptors()[des_idx];
    int length = des.first;
    QByteArray msg(length, 0);

    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QScopedPointer<Hash> hashalgo(lib->GetHashAlgorithm());
    bool good = true;

    for(int idx = 0; idx < count; idx++) {
      const char *tmsg = _messages[idx].constData() + msg_index;
      QByteArray xor_msg(QByteArray::fromRawData(tmsg, length));

      if(des.third[idx] != hashalgo->ComputeHash(xor_msg)) {
        qWarning() << "Xor message does not hash properly";
        _bad_message_hash.append(BadHash(des_idx, idx));
        good = false;
      }

      if(good) {
        Xor(msg, msg, xor_msg);
      }
    }

    if(good) {
      return msg;
    } else {
      return QByteArray();
    }
  }

  QPair<QByteArray, bool> BulkRound::GetBulkData(int max)
  {
    QPair<QByteArray, bool> pair = GetData(max);
    const QByteArray &data = pair.first;

    int length = data.size();
    if(length == 0) {
      return QPair<QByteArray, bool>(QByteArray(), false);
    }

    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QScopedPointer<Hash> hashalgo(lib->GetHashAlgorithm());

    QByteArray xor_message(length, 0);
    QVector<QByteArray> hashes;

    int my_idx = GetGroup().GetIndex(GetLocalId());

    foreach(const GroupContainer &gc, GetGroup().GetRoster()) {
      QByteArray seed = _anon_dh->GetSharedSecret(gc.third);

      if(hashes.size() == my_idx) {
        hashes.append(QByteArray());
        continue;
      }

      QByteArray msg(length, 0);
      QScopedPointer<Random> rng(lib->GetRandomNumberGenerator(seed));
      rng->GenerateBlock(msg);
      hashes.append(hashalgo->ComputeHash(msg));
      Xor(xor_message, xor_message, msg);
    }

    QByteArray my_xor_message = QByteArray(length, 0);
    Xor(my_xor_message, xor_message, data);
    SetMyXorMessage(my_xor_message);
    hashes[my_idx] = hashalgo->ComputeHash(my_xor_message);

    Descriptor descriptor(length, _anon_dh->GetPublicComponent(), hashes);
    SetMyDescriptor(descriptor);

    QByteArray my_desc;
    QDataStream desstream(&my_desc, QIODevice::WriteOnly);
    desstream << descriptor;
    return QPair<QByteArray, bool>(my_desc, false);
  }

  void BulkRound::ShuffleFinished()
  {
    if(!_shuffle_round->Successful()) {
      _bad_members = _shuffle_round->GetBadMembers();
      _state = Finished;
      Stop("ShuffleRound failed");
      return;
    }

    if(0 == _shuffle_sink.Count()) {
      _state = Finished;
      SetSuccessful(true);
      Stop("Round successfully finished -- no bulk messages");
      return;
    }

    PrepareBlameShuffle();

    GenerateXorMessages();

    _state = DataSharing;
    for(int idx = 0; idx < _offline_log.Count(); idx++) {
      QPair<QByteArray, Id> entry = _offline_log.At(idx);
      ProcessData(entry.first, entry.second);
    }

    _offline_log.Clear();
  }

  void BulkRound::GenerateXorMessages()
  {
    QByteArray msg;
    QDataStream stream(&msg, QIODevice::WriteOnly);
    stream << BulkData << GetRoundId();

    _expected_bulk_size = 0;
    for(int idx = 0; idx < _shuffle_sink.Count(); idx++) {
      QPair<QByteArray, ISender *> pair(_shuffle_sink.At(idx));
      Descriptor des = ParseDescriptor(pair.first);
      _descriptors.append(des);
      if(_my_idx == -1 && _my_descriptor == des) {
        _my_idx = idx;
      }
      stream << GenerateXorMessage(idx);
    }
    VerifiableBroadcast(msg);
  }

  BulkRound::Descriptor BulkRound::ParseDescriptor(const QByteArray &data)
  {
    Descriptor descriptor;
    QDataStream desstream(data);
    desstream >> descriptor;
    _expected_bulk_size += descriptor.first;
    return descriptor;
  }

  QByteArray BulkRound::GenerateXorMessage(int idx)
  {
    if(_my_idx == idx) {
      return _my_xor_message;
    }

    Descriptor descriptor = _descriptors[idx];
    QByteArray seed = GetDhKey()->GetSharedSecret(descriptor.second);

    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QScopedPointer<Hash> hashalgo(lib->GetHashAlgorithm());
    QScopedPointer<Random> rng(lib->GetRandomNumberGenerator(seed));

    QByteArray msg(descriptor.first, 0);
    rng->GenerateBlock(msg);
    QByteArray hash = hashalgo->ComputeHash(msg);

    if(descriptor.third[GetGroup().GetIndex(GetLocalId())] != hash) {
      qWarning() << "Invalid hash";
    }

    return msg;
  }

  void BulkRound::PrepareBlameShuffle()
  {
    QSharedPointer<Network> net(GetNetwork()->Clone());
    QVariantMap headers = net->GetHeaders();
    headers["bulk"] = false;
    net->SetHeaders(headers);

    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QScopedPointer<Hash> hashalgo(lib->GetHashAlgorithm());
    QByteArray roundid = GetRoundId().GetByteArray();
    roundid = hashalgo->ComputeHash(roundid);
    roundid = hashalgo->ComputeHash(roundid);
    Id sr_id(roundid);

    Round *pr = _create_shuffle(GetGroup(), GetCredentials(), sr_id, net,
        _get_blame_data);
    _shuffle_round = QSharedPointer<Round>(pr);

    _shuffle_round->SetSink(&_shuffle_sink);

    QObject::connect(_shuffle_round.data(), SIGNAL(Finished()),
        this, SLOT(BlameShuffleFinished()));
  }

  void BulkRound::BeginBlame()
  {
    _shuffle_sink.Clear();
    _shuffle_round->Start();
  }

  QPair<QByteArray, bool> BulkRound::GetBlameData(int)
  {
    QVector<BlameEntry> blame;
    foreach(const BadHash &bh, _bad_message_hash) {
      if(bh.first != _my_idx) {
        continue;
      }
      QByteArray dh_pub = GetGroup().GetPublicDiffieHellman(bh.second);
      QByteArray secret = _anon_dh->GetSharedSecret(dh_pub);
      blame.append(BlameEntry(bh.first, bh.second, secret));
    }

    if(blame.count()) {
      QByteArray msg;
      QDataStream stream(&msg, QIODevice::WriteOnly);
      stream << blame;
      return QPair<QByteArray, bool>(msg, false);
    } else {
      return QPair<QByteArray, bool>(QByteArray(), false);
    }
  }

  void BulkRound::BlameShuffleFinished()
  {
    for(int idx = 0; idx < _shuffle_sink.Count(); idx++) {
      QPair<QByteArray, ISender *> pair(_shuffle_sink.At(idx));
      QDataStream stream(pair.first);
      QVector<BlameEntry> blame_vector;
      stream >> blame_vector;
      if(blame_vector.count()) {
        ProcessBlame(blame_vector);
      }
    }
    _state = Finished;
    SetSuccessful(false);
    Stop("Round finished with blame");
  }

  void BulkRound::ProcessBlame(const QVector<BlameEntry> blame_vector)
  {
    Library *lib = CryptoFactory::GetInstance().GetLibrary();

    foreach(const BlameEntry &be, blame_vector) {
      if(!_bad_message_hash.contains(BadHash(be.first, be.second))) {
        qDebug() << "No knowledge of blame:" << be.first << be.second;
        continue;
      }

      const Descriptor &des = _descriptors[be.first];
      QByteArray msg(des.first, 0);
      QScopedPointer<Random> rng(lib->GetRandomNumberGenerator(be.third));
      rng->GenerateBlock(msg);

      QScopedPointer<Hash> hashalgo(lib->GetHashAlgorithm());
      QByteArray hash = hashalgo->ComputeHash(msg);
      if(hash == des.third[be.second] && !_bad_members.contains(be.second)) {
        qDebug() << "Blame verified for" << be.first << be.second;
        _bad_members.append(be.second);
      } else {
        qDebug() << "Blame could not be verified for" << be.first << be.second;
      }
    }
  }
}
}
