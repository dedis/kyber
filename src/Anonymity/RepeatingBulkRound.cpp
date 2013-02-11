#include <QCoreApplication>

#include "Connections/IOverlaySender.hpp"
#include "Connections/Network.hpp"
#include "Crypto/DsaPrivateKey.hpp"
#include "Crypto/Hash.hpp"
#include "Crypto/Serialization.hpp"
#include "Identity/PublicIdentity.hpp"
#include "Messaging/Request.hpp"
#include "Utils/QRunTimeError.hpp"
#include "Utils/Random.hpp"
#include "Utils/Serialization.hpp"
#include "Utils/Timer.hpp"
#include "Utils/TimerCallback.hpp"

#include "RepeatingBulkRound.hpp"
#include "BulkRound.hpp"
#include "ShuffleRound.hpp"

namespace Dissent {

using Crypto::CryptoRandom;
using Crypto::Hash;
using Identity::PublicIdentity;
using Messaging::Request;
using Utils::QRunTimeError;
using Utils::Random;
using Utils::Serialization;

namespace Anonymity {
  RepeatingBulkRound::RepeatingBulkRound(const Group &group,
      const PrivateIdentity &ident, const Id &round_id,
      QSharedPointer<Network> network, GetDataCallback &get_data,
      CreateRound create_shuffle) :
    Round(group, ident, round_id, network, get_data),
    _get_shuffle_data(this, &RepeatingBulkRound::GetShuffleData),
    _state(Offline),
    _phase(0),
    _stop_next(false),
    _last_phase(0)
  {
    QVariantHash headers = GetNetwork()->GetHeaders();
    headers["bulk"] = true;
    GetNetwork()->SetHeaders(headers);

    _anon_key = QSharedPointer<AsymmetricKey>(new Crypto::DsaPrivateKey());
    QSharedPointer<Network> net(GetNetwork()->Clone());
    headers["bulk"] = false;
    net->SetHeaders(headers);

    Id sr_id(Hash().ComputeHash(GetRoundId().GetByteArray()));

    _shuffle_round = create_shuffle(GetGroup(), GetPrivateIdentity(), sr_id, net,
        _get_shuffle_data);
    _shuffle_round->SetSink(&_shuffle_sink);

    QObject::connect(_shuffle_round.data(), SIGNAL(Finished()),
        this, SLOT(ShuffleFinished()));
  }

  void RepeatingBulkRound::OnStart()
  {
    Round::OnStart();
    QVector<CryptoRandom> anon_rngs;

    foreach(PublicIdentity gc, GetGroup().GetRoster()) {
      QByteArray seed = _anon_dh.GetSharedSecret(gc.GetDhKey());
      CryptoRandom rand(seed);
      anon_rngs.append(rand);
    }

    Utils::TimerCallback *cb = new Utils::TimerMethod<RepeatingBulkRound, int>(
        this, &RepeatingBulkRound::CheckState, 0);
    _check_event = Utils::Timer::GetInstance().QueueCallback( cb, 60000, 60000);

    SetAnonymousRngs(anon_rngs);

    SetState(Shuffling);
    _shuffle_round->Start();
  }

  void RepeatingBulkRound::OnStop()
  {
    _check_event.Stop();
    Round::OnStop();
  }

  void RepeatingBulkRound::CheckState(const int &)
  {
    if(_last_phase != _phase) {
      qDebug() << "In CheckState, system appears to be progressing normally.";
      _last_phase = _phase;
      return;
    } else if(_state == Shuffling) {
      qDebug() << "In CheckState, shuffling";
      return;
    }

    qDebug() << "In CheckState, progress seems slow.  Missing" <<
      (_messages.size() - _received_messages) << "ciphertexts for:";
    for(int idx = 0; idx < _messages.size(); idx++) {
      if(_messages[idx].isEmpty()) {
        qDebug() << "\t" << GetGroup().GetId(idx);
      }
    }
  }

  void RepeatingBulkRound::IncomingData(const Request &notification)
  {
    if(Stopped()) {
      qWarning() << "Received a message on a closed session:" << ToString();
      return;
    }

    QSharedPointer<Connections::IOverlaySender> sender =
      notification.GetFrom().dynamicCast<Connections::IOverlaySender>();
    if(!sender) {
      qDebug() << ToString() << " received wayward message from: " <<
        notification.GetFrom()->ToString();
      return;
    }

    const Id &id = sender->GetRemoteId();
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

  void RepeatingBulkRound::ProcessData(const Id &from, const QByteArray &data)
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

  void RepeatingBulkRound::ProcessDataBase(const Id &from, const QByteArray &data)
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
    uint phase;
    stream >> mtype >> round_id >> phase;

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

    if(_phase != phase) {
      if(_phase == phase - 1 && _state == DataSharing) {
        _log.Pop();
        _offline_log.Append(data, from);
        return;
      } else {
        throw QRunTimeError("Received a message for phase: " + 
            QString::number(phase) + ", while in phase: " +
            QString::number(_phase));
      }
    } else if(_state == PhasePreparation) {
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

  void RepeatingBulkRound::HandleBulkData(QDataStream &stream, const Id &from)
  {
    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
      ": received bulk data from " << GetGroup().GetIndex(from) << from.ToString()
      << "Have" << (_received_messages + 1) << "expecting" << _messages.count();

    if(_state != DataSharing) {
      throw QRunTimeError("Received a misordered BulkData message");
    }

    uint idx = GetGroup().GetIndex(from);
    if(!_messages[idx].isEmpty()) {
      throw QRunTimeError("Already have bulk data.");
    }

    QByteArray payload;
    stream >> payload;

    if(static_cast<uint>(payload.size()) != _expected_bulk_size) {
      throw QRunTimeError("Incorrect bulk message length, got " +
          QString::number(payload.size()) + " expected " +
          QString::number(_expected_bulk_size));
    }

    _messages[idx] = payload;

    if(++_received_messages == static_cast<uint>(GetGroup().Count())) {
      ProcessMessages();

      SetState(PhasePreparation);
      qDebug() << "In" << ToString() << "ending phase.";
      _phase++;
      if(!PrepForNextPhase()) {
        return;
      }

      SetState(DataSharing);

      uint count = static_cast<uint>(_offline_log.Count());
      for(uint idx = 0; idx < count; idx++) {
        QPair<QByteArray, Id> entry = _offline_log.At(idx);
        ProcessData(entry.second, entry.first);
      }

      _offline_log.Clear();

      NextPhase();
    }
  }

  void RepeatingBulkRound::ProcessMessages()
  {
    uint size = GetGroup().Count();

    QByteArray cleartext(_expected_bulk_size, 0);
    foreach(QByteArray ciphertext, _messages) {
      Xor(cleartext, cleartext, ciphertext);
    }

    uint msg_idx = 0;
    for(uint member_idx = 0; member_idx < size; member_idx++) {
      int length = _message_lengths[member_idx] + _header_lengths[member_idx];
      QByteArray tcleartext = QByteArray::fromRawData(cleartext.constData() + msg_idx, length);
      msg_idx += length;
      QByteArray msg = ProcessMessage(tcleartext, member_idx);

      if(!msg.isEmpty()) {
        qDebug() << ToString() << "received a valid message.";
        PushData(GetSharedPointer(), msg);
      }
    }
  }

  QByteArray RepeatingBulkRound::ProcessMessage(const QByteArray &cleartext, uint member_idx)
  {
    uint found_phase = Serialization::ReadInt(cleartext, 0);
    if(found_phase != _phase) {
      qWarning() << "Received a message for an invalid phase:" << found_phase;
      _message_lengths[member_idx] = 0;
      return QByteArray();
    }

    QSharedPointer<AsymmetricKey> verification_key(_descriptors[member_idx].second);
    uint vkey_size = verification_key->GetSignatureLength();

    QByteArray base = QByteArray::fromRawData(cleartext.constData(), cleartext.size() - vkey_size);
    QByteArray sig = QByteArray::fromRawData(cleartext.constData() + cleartext.size() - vkey_size, vkey_size);
    if(verification_key->Verify(base, sig)) {
      _message_lengths[member_idx] = Serialization::ReadInt(cleartext, 4);
      return base.mid(8);
    } else {
      qWarning() << "Unable to verify message for peer at" << member_idx;
      _message_lengths[member_idx] = 0;
      return QByteArray();
    }
  }

  bool RepeatingBulkRound::PrepForNextPhase()
  {
    if(!ProcessEvents()) {
      return false;
    }

    if(_stop_next) {
      SetInterrupted();
      Stop("Stopped for join");
      return false;
    }

    _log.Clear();
    uint group_size = static_cast<uint>(GetGroup().Count());
    _messages = QVector<QByteArray>(group_size);
    _received_messages = 0;

    _expected_bulk_size = 0;
    for(uint idx = 0; idx < group_size; idx++) {
      _expected_bulk_size += _header_lengths[idx] + _message_lengths[idx];
    }

    return true;
  }

  void RepeatingBulkRound::NextPhase()
  {
    qDebug() << "In" << ToString() << "starting phase.";
    QByteArray xor_msg = GenerateXorMessage();
    QByteArray packet;
    QDataStream stream(&packet, QIODevice::WriteOnly);
    stream << BulkData << GetRoundId() << _phase << xor_msg;
    VerifiableBroadcast(packet);
  }

  QByteArray RepeatingBulkRound::GenerateXorMessage()
  {
    QByteArray msg;
    uint size = static_cast<uint>(_descriptors.size());
    for(uint idx = 0; idx < size; idx++) {
      if(idx == _my_idx) {
        msg.append(GenerateMyXorMessage());
        continue;
      }
      uint length = _message_lengths[idx] + _header_lengths[idx];
      QByteArray tmsg(length, 0);
      _descriptors[idx].third.GenerateBlock(tmsg);
      msg.append(tmsg);
    }

    return msg;
  }

  QByteArray RepeatingBulkRound::GenerateMyXorMessage()
  {
    QByteArray cleartext = GenerateMyCleartextMessage();

    uint length = cleartext.size();
    uint my_idx = GetGroup().GetIndex(GetLocalId());
    QByteArray xor_msg(length, 0);
    _expected_msgs.clear();
    uint count = static_cast<uint>(GetGroup().Count());
    for(uint idx = 0; idx < count; idx++) {
      if(idx == my_idx) {
        Xor(xor_msg, xor_msg, cleartext);
        _expected_msgs.append(QByteArray());
        continue;
      }

      QByteArray tmsg(length, 0);
      _anon_rngs[idx].GenerateBlock(tmsg);
      _expected_msgs.append(tmsg);
      Xor(xor_msg, xor_msg, tmsg);
    }

    _expected_msgs[_my_idx] = xor_msg;
    return xor_msg;
  }

  QByteArray RepeatingBulkRound::GenerateMyCleartextMessage()
  {
    QPair<QByteArray, bool> pair = GetData(4096);
    const QByteArray cur_msg = _next_msg;
    _next_msg = pair.first;

    QByteArray cleartext(8, 0);
    Serialization::WriteInt(_phase, cleartext, 0);
    Serialization::WriteInt(_next_msg.size(), cleartext, 4);
    cleartext.append(cur_msg);
    QByteArray sig = _anon_key->Sign(cleartext);
    cleartext.append(sig);

    return cleartext;
  }

  QPair<QByteArray, bool> RepeatingBulkRound::GetShuffleData(int)
  {
    QByteArray msg;
    QDataStream stream(&msg, QIODevice::WriteOnly);
    QSharedPointer<AsymmetricKey> pub_key(_anon_key->GetPublicKey());
    stream << pub_key << _anon_dh.GetPublicComponent();
    _shuffle_data = msg;
    return QPair<QByteArray, bool>(msg, false);
  }

  void RepeatingBulkRound::ShuffleFinished()
  {
    if(!_shuffle_round->Successful()) {
      _bad_members = _shuffle_round->GetBadMembers();
      _state = Finished;
      Stop("ShuffleRound failed");
      return;
    }

    if(_shuffle_sink.Count() != GetGroup().Count()) {
      qWarning() << "Did not receive a descriptor from everyone.";
    }

    uint count = static_cast<uint>(_shuffle_sink.Count());
    for(uint idx = 0; idx < count; idx++) {
      QPair<QSharedPointer<ISender>, QByteArray> pair(_shuffle_sink.At(idx));
      _descriptors.append(ParseDescriptor(pair.second));
      _header_lengths.append(8 + (_descriptors.last().second->GetSignatureLength()));
      _message_lengths.append(0);
      if(_shuffle_data == pair.second) {
        _my_idx = idx;
      }
    }

    SetState(PhasePreparation);
    if(!PrepForNextPhase()) {
      return;
    }

    SetState(DataSharing);
    NextPhase();

    count = static_cast<uint>(_offline_log.Count());
    for(uint idx = 0; idx < count; idx++) {
      QPair<QByteArray, Id> entry = _offline_log.At(idx);
      ProcessData(entry.second, entry.first);
    }

    _offline_log.Clear();
  }

  RepeatingBulkRound::Descriptor RepeatingBulkRound::ParseDescriptor(const QByteArray &bdes)
  {
    QDataStream stream(bdes);
    QSharedPointer<AsymmetricKey> key_pub;
    QByteArray dh_pub;
    stream >> key_pub >> dh_pub;

    if(!key_pub->IsValid()) {
      qWarning() << "Received an invalid signing key during the shuffle.";
    }

    QByteArray seed = GetDhKey().GetSharedSecret(dh_pub);
    CryptoRandom rand(seed);
    return Descriptor(dh_pub, key_pub, rand);
  }
}
}
