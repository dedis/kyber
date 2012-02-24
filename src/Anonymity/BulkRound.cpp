#include "Connections/Connection.hpp"
#include "Connections/Network.hpp"
#include "Crypto/DiffieHellman.hpp"
#include "Crypto/Hash.hpp"
#include "Crypto/Library.hpp"
#include "Messaging/Request.hpp"
#include "Utils/QRunTimeError.hpp"
#include "Utils/Random.hpp"
#include "Utils/Serialization.hpp"

#include "BulkRound.hpp"
#include "ShuffleRound.hpp"

using Dissent::Connections::Connection;
using Dissent::Crypto::CryptoFactory;
using Dissent::Crypto::DiffieHellman;
using Dissent::Crypto::Hash;
using Dissent::Crypto::Library;
using Dissent::Messaging::Request;
using Dissent::Utils::QRunTimeError;
using Dissent::Utils::Random;
using Dissent::Utils::Serialization;

namespace Dissent {
namespace Anonymity {
  BulkRound::BulkRound(const Group &group, const Credentials &creds,
      const Id &round_id, QSharedPointer<Network> network,
      GetDataCallback &get_data, CreateRound create_shuffle) :
    Round(group, creds, round_id, network, get_data),
    _app_broadcast(true),
    _my_idx(-1),
    _create_shuffle(create_shuffle),
    _get_bulk_data(this, &BulkRound::GetBulkData),
    _get_blame_data(this, &BulkRound::GetBlameData),
    _state(Offline),
    _messages(GetGroup().Count()),
    _received_messages(0),
    _is_leader(GetGroup().GetLeader() == GetLocalId())
  {
    QVariantHash headers = GetNetwork()->GetHeaders();
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

    _shuffle_round = _create_shuffle(GetGroup(), GetCredentials(), sr_id, net,
        _get_bulk_data);
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

  void BulkRound::IncomingData(const Request &notification)
  {
    if(Stopped()) {
      qWarning() << "Received a message on a closed session:" << ToString();
      return;
    }
      
    QSharedPointer<Connection> con = notification.GetFrom().dynamicCast<Connection>();
    if(!con) {
      qDebug() << ToString() << " received wayward message from: " <<
        notification.GetFrom()->ToString();
      return;
    }

    const Id &id = con->GetRemoteId();
    if(!GetGroup().Contains(id)) {
      qDebug() << ToString() << " received wayward message from: " << 
        notification.GetFrom()->ToString();
      return;
    }

    QVariantHash msg = notification.GetData().toHash();

    bool bulk = msg.value("bulk").toBool();
    if(bulk) {
      ProcessData(id, msg.value("data").toByteArray());
    } else {
      _shuffle_round->IncomingData(notification);
    }
  }

  void BulkRound::ProcessData(const Id &from, const QByteArray &data)
  {
    _log.Append(data, from);
    try {
      ProcessDataBase(from, data);
    } catch (QRunTimeError &err) {
      qWarning() << GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
        "received a message from" << GetGroup().GetIndex(from) << from.ToString() <<
        "in session / round" << GetRoundId().ToString() << "in state" <<
        StateToString(_state) << "causing the following exception: " << err.What();
      _log.Pop();
      return;
    }
  }

  void BulkRound::ProcessDataBase(const Id &from, const QByteArray &data)
  {
    QByteArray payload;
    if(!Verify(from, data, payload)) {
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
      case LoggedBulkData:
        HandleLoggedBulkData(stream, from);
        break;
      case AggregatedBulkData:
        HandleAggregatedBulkData(stream, from);
        break;
      default:
        throw QRunTimeError("Unknown message type");
    }
  }

  void BulkRound::HandleLoggedBulkData(QDataStream &stream, const Id &from)
  {
    if(from == GetLocalId()) {
      return;
    }

    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
      ": received logged bulk data from " << GetGroup().GetIndex(from) <<
      from.ToString();

    if(GetGroup().GetLeader() != from) {
      throw QRunTimeError("Received logged bulk data from non-leader.");
    }

    if(_state != ReceivingLeaderData) {
      throw QRunTimeError("Not expected at this time.");
    }

    QByteArray binary_log;
    stream >> binary_log;
    Log log(binary_log);
    
    if(log.Count() != GetGroup().Count()) {
      throw QRunTimeError("Incorrect number of log messages.");
    }

    _state = ProcessingLeaderData;
    for(int idx = 0; idx < log.Count(); idx++) {
      const QPair<QByteArray, Id> &res = log.At(idx);
      try {
        ProcessDataBase(res.second, res.first);
      } catch (QRunTimeError &err) {
        const Id &from = res.second;
        qWarning() << GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
          "leader equivocated in message from" << GetGroup().GetIndex(from) <<
          from.ToString() << "in session / round" << GetRoundId().ToString() <<
          "in state" << StateToString(_state) <<
          "causing the following exception: " << err.What();
        // Should end round.
        break;
      }
    }
  }

  void BulkRound::HandleAggregatedBulkData(QDataStream &stream, const Id &from)
  {
    if(from == GetLocalId()) {
      return;
    }

    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
      ": received aggregated bulk data from " << GetGroup().GetIndex(from) <<
      from.ToString();

    if(GetGroup().GetLeader() != from) {
      throw QRunTimeError("Received aggregated bulk data from non-leader.");
    }

    if(_state != ReceivingLeaderData) {
      throw QRunTimeError("Not expected at this time.");
    }

    QVector<QByteArray> cleartexts;
    stream >> cleartexts;

    const QVector<Descriptor> &des = GetDescriptors();

    if(cleartexts.count() != des.count()) {
      throw QRunTimeError("Cleartext count does not match descriptor count: " +
          QString::number(cleartexts.count()) + " " +
          QString::number(des.count()));
    }

    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QScopedPointer<Hash> hashalgo(lib->GetHashAlgorithm());

    for(int idx = 0; idx < cleartexts.count(); idx++) {
      QByteArray cleartext = cleartexts[idx];
      QByteArray hash = hashalgo->ComputeHash(cleartext);
      if(hash != des[idx].CleartextHash()) {
        throw QRunTimeError("Cleartext hash does not match descriptor hash.");
      }
      if(!cleartext.isEmpty()) {
        PushData(GetSharedPointer(), cleartext);
      }
    }

    Finish();
  }

  void BulkRound::HandleBulkData(QDataStream &stream, const Id &from)
  {
    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
      ": received bulk data from " << GetGroup().GetIndex(from) << from.ToString();

    if(IsLeader() || !_app_broadcast) {
      if(_state != DataSharing) {
        throw QRunTimeError("Received a misordered BulkData message");
      }
    } else if(_app_broadcast && _state != ProcessingLeaderData) {
      throw QRunTimeError("Waiting for data from leader, received something else.");
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
      Finish();
    }
  }

  void BulkRound::Finish()
  {
    if(_bad_message_hash.isEmpty()) {
      if(_app_broadcast && IsLeader()) {
        QByteArray msg;
        QDataStream stream(&msg, QIODevice::WriteOnly);
        stream << AggregatedBulkData << GetRoundId() << _cleartexts;
        VerifiableBroadcast(msg);
      }
      _state = Finished;
      SetSuccessful(true);
      Stop("Round successfully finished");
    } else {
      if(_app_broadcast && IsLeader()) {
        QByteArray msg;
        QDataStream stream(&msg, QIODevice::WriteOnly);
        stream << LoggedBulkData << GetRoundId() << _log.Serialize();
        VerifiableBroadcast(msg);
      }
      BeginBlame();
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
      _cleartexts.append(cleartext);
      if(!cleartext.isEmpty()) {
        PushData(GetSharedPointer(), cleartext);
      }
      index += _descriptors[idx].Length();
    }
  }

  QByteArray BulkRound::ProcessMessage(int des_idx, int msg_index)
  {
    int count = _messages.size();
    const Descriptor &des = GetDescriptors()[des_idx];
    int length = des.Length();
    QByteArray msg(length, 0);

    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QScopedPointer<Hash> hashalgo(lib->GetHashAlgorithm());
    bool good = true;

    for(int idx = 0; idx < count; idx++) {
      const char *tmsg = _messages[idx].constData() + msg_index;
      QByteArray xor_msg(QByteArray::fromRawData(tmsg, length));

      if(des.XorMessageHashes()[idx] != hashalgo->ComputeHash(xor_msg)) {
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

    if(data.size() == 0) {
      return QPair<QByteArray, bool>(QByteArray(), false);
    }

    CreateDescriptor(pair.first);

    QByteArray my_desc;
    QDataStream desstream(&my_desc, QIODevice::WriteOnly);
    desstream << GetMyDescriptor();
    return QPair<QByteArray, bool>(my_desc, false);
  }

  void BulkRound::CreateDescriptor(const QByteArray &data)
  {
    int length = data.size();

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

    QByteArray hash = hashalgo->ComputeHash(data);

    Descriptor descriptor(length, _anon_dh->GetPublicComponent(), hashes, hash);
    SetMyDescriptor(descriptor);
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

    if(_app_broadcast && !IsLeader()) {
      _state = ReceivingLeaderData;
    } else {
      _state = DataSharing;
    }

    for(int idx = 0; idx < _offline_log.Count(); idx++) {
      QPair<QByteArray, Id> entry = _offline_log.At(idx);
      ProcessData(entry.second, entry.first);
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
      QPair<QSharedPointer<ISender>, QByteArray> pair(_shuffle_sink.At(idx));
      Descriptor des = ParseDescriptor(pair.second);
      _descriptors.append(des);
      if(_my_idx == -1 && _my_descriptor == des) {
        _my_idx = idx;
      }
      stream << GenerateXorMessage(idx);
    }

    if(_app_broadcast) {
      VerifiableSend(GetGroup().GetLeader(), msg);
    } else {
      VerifiableBroadcast(msg);
    }
  }

  BulkRound::Descriptor BulkRound::ParseDescriptor(const QByteArray &data)
  {
    Descriptor descriptor;
    QDataStream desstream(data);
    desstream >> descriptor;
    _expected_bulk_size += descriptor.Length();
    return descriptor;
  }

  QByteArray BulkRound::GenerateXorMessage(int idx)
  {
    if(_my_idx == idx) {
      return _my_xor_message;
    }

    Descriptor descriptor = _descriptors[idx];
    QByteArray seed = GetDhKey()->GetSharedSecret(descriptor.PublicDh());

    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QScopedPointer<Hash> hashalgo(lib->GetHashAlgorithm());
    QScopedPointer<Random> rng(lib->GetRandomNumberGenerator(seed));

    QByteArray msg(descriptor.Length(), 0);
    rng->GenerateBlock(msg);
    QByteArray hash = hashalgo->ComputeHash(msg);

    if(descriptor.XorMessageHashes()[GetGroup().GetIndex(GetLocalId())] != hash) {
      qWarning() << "Invalid hash";
    }

    return msg;
  }

  void BulkRound::PrepareBlameShuffle()
  {
    QSharedPointer<Network> net(GetNetwork()->Clone());
    QVariantHash headers = net->GetHeaders();
    headers["bulk"] = false;
    net->SetHeaders(headers);

    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QScopedPointer<Hash> hashalgo(lib->GetHashAlgorithm());
    QByteArray roundid = GetRoundId().GetByteArray();
    roundid = hashalgo->ComputeHash(roundid);
    roundid = hashalgo->ComputeHash(roundid);
    Id sr_id(roundid);

    _shuffle_round = _create_shuffle(GetGroup(), GetCredentials(), sr_id, net,
        _get_blame_data);

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
      QPair<QSharedPointer<ISender>, QByteArray> pair(_shuffle_sink.At(idx));
      QDataStream stream(pair.second);
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
      QByteArray msg(des.Length(), 0);
      QScopedPointer<Random> rng(lib->GetRandomNumberGenerator(be.third));
      rng->GenerateBlock(msg);

      QScopedPointer<Hash> hashalgo(lib->GetHashAlgorithm());
      QByteArray hash = hashalgo->ComputeHash(msg);
      if(hash == des.XorMessageHashes()[be.second] && !_bad_members.contains(be.second)) {
        qDebug() << "Blame verified for" << be.first << be.second;
        _bad_members.append(be.second);
      } else {
        qDebug() << "Blame could not be verified for" << be.first << be.second;
      }
    }
  }

  bool operator==(const BulkRound::Descriptor &lhs,
      const BulkRound::Descriptor &rhs)
  {
    return (lhs.Length() == rhs.Length()) &&
      (lhs.PublicDh() == rhs.PublicDh()) &&
      (lhs.XorMessageHashes() == rhs.XorMessageHashes()) &&
      (lhs.CleartextHash() == rhs.CleartextHash());
  }

  QDataStream &operator<<(QDataStream &stream,
      const BulkRound::Descriptor &des)
  {
    stream << des.Length();
    stream << des.PublicDh();
    stream << des.XorMessageHashes();
    stream << des.CleartextHash();
    return stream;
  }

  QDataStream &operator>>(QDataStream &stream, BulkRound::Descriptor &des)
  {
    int length;
    stream >> length;

    QByteArray dh;
    stream >> dh;

    QVector<QByteArray> hashes;
    stream >> hashes;

    QByteArray hash;
    stream >> hash;

    des = BulkRound::Descriptor(length, dh, hashes, hash);
    return stream;
  }
}
}
