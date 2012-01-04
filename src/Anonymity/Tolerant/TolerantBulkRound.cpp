#include "Anonymity/BulkRound.hpp"
#include "Anonymity/ShuffleRound.hpp"
#include "Connections/Connection.hpp"
#include "Connections/Network.hpp"
#include "Crypto/DiffieHellman.hpp"
#include "Crypto/Hash.hpp"
#include "Crypto/Library.hpp"
#include "Crypto/Serialization.hpp"
#include "Messaging/RpcRequest.hpp"
#include "Utils/QRunTimeError.hpp"
#include "Utils/Random.hpp"
#include "Utils/Serialization.hpp"

#include "TolerantBulkRound.hpp"
#include "BlameMatrix.hpp"

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
namespace Tolerant {
  TolerantBulkRound::TolerantBulkRound(const Group &group,
      const Credentials &creds, const Id &round_id, QSharedPointer<Network> network,
      GetDataCallback &get_data, CreateRound create_shuffle) :
    Round(group, creds, round_id, network, get_data),
    _is_server(GetGroup().GetSubgroup().Contains(GetLocalId())),
    _server_public_dh_keys(GetGroup().GetSubgroup().Count()),
    _user_public_dh_keys(GetGroup().Count()),
    _secrets_with_servers(GetGroup().GetSubgroup().Count()),
    _rngs_with_servers(GetGroup().GetSubgroup().Count()),
    _get_key_shuffle_data(this, &TolerantBulkRound::GetKeyShuffleData),
    _get_blame_shuffle_data(this, &TolerantBulkRound::GetBlameShuffleData),
    _create_shuffle(create_shuffle),
    _state(Offline),
    _crypto_lib(CryptoFactory::GetInstance().GetLibrary()),
    _user_dh_key(_crypto_lib->CreateDiffieHellman()),
    _anon_signing_key(_crypto_lib->CreatePrivateKey()),
    _phase(0),
    _message_randomizer(_user_dh_key->GetPrivateComponent()),
    _message_history(GetGroup().Count(), GetGroup().GetSubgroup().Count()),
    _user_idx(GetGroup().GetIndex(GetLocalId())),
    _looking_for_evidence(NotLookingForEvidence),
    _user_alibi_data(GetGroup().Count(), GetGroup().GetSubgroup().Count()),
    _server_alibi_data(GetGroup().Count(), GetGroup().Count())
  {
    QVariantMap headers = GetNetwork()->GetHeaders();
    headers["round"] = Header_Bulk;
    GetNetwork()->SetHeaders(headers);

    // Set up shared secrets
    if(_is_server) {
      _server_dh_key = QSharedPointer<DiffieHellman>(_crypto_lib->CreateDiffieHellman());
      _secrets_with_users.resize(GetGroup().Count());
      _rngs_with_users.resize(GetGroup().Count());
      _server_idx = GetGroup().GetSubgroup().GetIndex(GetLocalId());
    }

    // Set up signing key shuffle
    QSharedPointer<Network> net(GetNetwork()->Clone());
    headers["round"] = Header_SigningKeyShuffle;
    net->SetHeaders(headers);

    QScopedPointer<Hash> hashalgo(_crypto_lib->GetHashAlgorithm());
    Id sr_id(hashalgo->ComputeHash(GetRoundId().GetByteArray()));

    Round *pr = _create_shuffle(GetGroup(), GetCredentials(), sr_id,
        net, _get_key_shuffle_data);
    _key_shuffle_round = QSharedPointer<Round>(pr);
    _key_shuffle_round->SetSink(&_key_shuffle_sink);

    QObject::connect(_key_shuffle_round.data(), SIGNAL(Finished()),
        this, SLOT(KeyShuffleFinished()));
  }

  bool TolerantBulkRound::Start()
  {
    if(!Round::Start()) {
      return false;
    }

    qDebug() << "Starting Round. Server:" << _is_server;

    _state = ExchangingDhKeys;
    BroadcastPublicDhKey(MessageType_UserKey, _user_dh_key);

    if(_is_server) {
      BroadcastPublicDhKey(MessageType_ServerKey, _server_dh_key);
    }

    return true;
  }

  void TolerantBulkRound::IncomingData(RpcRequest &notification)
  {
    if(Stopped()) {
      qWarning() << "Received a message on a closed repeating bulk session:" << ToString();
      return;
    }
      
    Dissent::Messaging::ISender *from = notification.GetFrom();
    Connection *con = dynamic_cast<Connection *>(from);
    const Id &id = con->GetRemoteId();
    if(con == 0 || !GetGroup().Contains(id)) {
      qDebug() << ToString() << " received wayward message from: " << from->ToString();
      return;
    }

    int round = notification.GetMessage()["round"].toInt();
    switch(round) {
      case Header_Bulk:
        ProcessData(notification.GetMessage()["data"].toByteArray(), id);
        break;
      case Header_SigningKeyShuffle:
        qDebug() << "Signing key msg";
        _key_shuffle_round->IncomingData(notification);
        break;
      case Header_BlameShuffle:
        qDebug() << "Blame msg";
        _blame_shuffle_round->IncomingData(notification);
        break;
      default:
        qWarning() << "Got message with unknown round header:" << round;
    }
  }

  void TolerantBulkRound::ProcessData(const QByteArray &data, const Id &from)
  {
    _log.Append(data, from);
    try {
      ProcessDataBase(data, from);
    } catch (QRunTimeError &err) {
      qWarning() << _user_idx << GetLocalId().ToString() <<
        "received a message from" << GetGroup().GetIndex(from) << from.ToString() <<
        "in session / round" << GetRoundId().ToString() << "in state" <<
        StateToString(_state) << "causing the following exception: " << err.What();
      _log.Pop();
      return;
    }
  }

  void TolerantBulkRound::ProcessDataBase(const QByteArray &data, const Id &from)
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
    uint phase;
    stream >> mtype >> round_id >> phase;

    MessageType msg_type = (MessageType) mtype;

    Id rid(round_id);
    if(rid != GetRoundId()) {
      throw QRunTimeError("Not this round: " + rid.ToString() + " " +
          GetRoundId().ToString());
    }

    if(_state == SigningKeyShuffling) {
      _log.Pop();
      _offline_log.Append(data, from);
      return;
    }

    if(_phase != phase) {
      if(_phase == phase - 1 && (_state == DataSharing || _state == BlameWaitingForShuffle)) {
        _log.Pop();
        _offline_log.Append(data, from);
        return;
      } else {
        throw QRunTimeError("Received a message for phase: " + 
            QString::number(phase) + ", while in phase: " +
            QString::number(_phase));
      }
    }

    switch(msg_type) {
      case MessageType_UserKey:
        HandleUserKey(stream, from);
        break;
      case MessageType_ServerKey:
        HandleServerKey(stream, from);
        break;
      case MessageType_UserBulkData:
        HandleUserBulkData(stream, from);
        break;
      case MessageType_ServerBulkData:
        HandleServerBulkData(stream, from);
        break;
      case MessageType_UserAlibiData:
        HandleUserAlibiData(stream, from);
        break;
      case MessageType_ServerAlibiData:
        HandleServerAlibiData(stream, from);
        break;
      case MessageType_UserProofData:
        HandleUserProofData(stream, from);
        break;
      case MessageType_ServerProofData:
        HandleServerProofData(stream, from);
        break;
      default:
        throw QRunTimeError("Unknown message type");
    }

  }


  void TolerantBulkRound::HandleUserKey(QDataStream &stream, const Id &from)
  {
    qDebug() << _user_idx << GetLocalId().ToString() <<
      ": received user's public DH key from " << GetGroup().GetIndex(from) << from.ToString();

    if(_state != ExchangingDhKeys) {
      throw QRunTimeError("Received a misordered user DH key message");
    }

    QByteArray payload;
    stream >> payload;

    uint key_size = _user_dh_key->GetPublicComponent().size();
    if(static_cast<uint>(payload.size()) != key_size) {
      throw QRunTimeError("Incorrect user DH key message length, got " +
          QString::number(payload.size()) + " expected " +
          QString::number(key_size));
    }

    qDebug() << "Recording public key from user " << GetGroup().GetIndex(from) << from.ToString();
    uint idx = GetGroup().GetIndex(from);
    _user_public_dh_keys[idx] = payload;

    if(_is_server) {
      qDebug() << "Recording shared secret with user " << GetGroup().GetIndex(from) << from.ToString();

      QByteArray secret = _server_dh_key->GetSharedSecret(payload);
      _secrets_with_users[idx] = secret;

      _rngs_with_users[idx] = QSharedPointer<Random>(_crypto_lib->GetRandomNumberGenerator(secret));
    } else {
      qDebug() << "User ignoring user key from" << GetGroup().GetIndex(from) << from.ToString();
    }

    if(HasAllSharedSecrets()) {
      qDebug() << "Have all shared secrets!";
      RunKeyShuffle();
    }
  }

  void TolerantBulkRound::HandleServerKey(QDataStream &stream, const Id &from)
  {
    qDebug() << _user_idx << GetLocalId().ToString() <<
      ": received server's public DH key from " << GetGroup().GetIndex(from) << from.ToString();

    if(_state != ExchangingDhKeys) {
      throw QRunTimeError("Received a misordered server DH key message");
    }

    QByteArray payload;
    stream >> payload;

    uint key_size = _user_dh_key->GetPublicComponent().size();
    if(static_cast<uint>(payload.size()) != key_size) {
      throw QRunTimeError("Incorrect server DH key message length, got " +
          QString::number(payload.size()) + " expected " +
          QString::number(key_size));
    }

    qDebug() << "Recording shared secret with server " << GetGroup().GetIndex(from) << from.ToString();

    uint idx = GetGroup().GetIndex(from);
    QByteArray secret = _user_dh_key->GetSharedSecret(payload);
    _secrets_with_servers[idx] = secret;
    _server_public_dh_keys[idx] = payload;

    _rngs_with_servers[idx] = QSharedPointer<Random>(_crypto_lib->GetRandomNumberGenerator(secret));

    if(HasAllSharedSecrets()) {
      qDebug() << "Have all shared secrets!";
      RunKeyShuffle();
    }
  }

  bool TolerantBulkRound::HasAllSharedSecrets() 
  {
    // Make sure node has one secret with each server
    // and if it's a server, it should have a secret with
    // every user too.
    return !_secrets_with_servers.count(QByteArray()) &&
      (!_is_server || !_secrets_with_users.count(QByteArray()));
  }

  void TolerantBulkRound::BroadcastPublicDhKey(MessageType mtype, QSharedPointer<DiffieHellman> key)
  {
    QByteArray packet;
    QDataStream stream(&packet, QIODevice::WriteOnly);
    stream << mtype << GetRoundId() << _phase << key->GetPublicComponent();
    VerifiableBroadcast(packet);
  }

  void TolerantBulkRound::RunKeyShuffle()
  {
    _state = SigningKeyShuffling;
    _key_shuffle_round->Start();
  }

  QPair<QByteArray, bool> TolerantBulkRound::GetKeyShuffleData(int)
  {
    QByteArray msg;
    QDataStream stream(&msg, QIODevice::WriteOnly);
    QSharedPointer<AsymmetricKey> pub_key(_anon_signing_key->GetPublicKey());
    stream << pub_key;
    _key_shuffle_data = msg;
    return QPair<QByteArray, bool>(msg, false);
  }

  QSharedPointer<TolerantBulkRound::AsymmetricKey> TolerantBulkRound::ParseSigningKey(const QByteArray &bdes)
  {
    QDataStream stream(bdes);
    QSharedPointer<AsymmetricKey> key_pub;
    stream >> key_pub;

    if(!key_pub->IsValid()) {
      qWarning() << "Received an invalid signing key during the shuffle.";
    }

    return key_pub;
  }

  void TolerantBulkRound::HandleUserBulkData(QDataStream &stream, const Id &from)
  {
    qDebug() << _user_idx << GetLocalId().ToString() <<
      ": received bulk user data from " << GetGroup().GetIndex(from) << from.ToString();

    if(_state != DataSharing && _state != BlameWaitingForShuffle) {
      throw QRunTimeError("Received a misordered UserBulkData message");
    }

    uint idx = GetGroup().GetIndex(from);
    if(!_user_messages[idx].isEmpty()) {
      throw QRunTimeError("Already have bulk user data.");
    }

    QByteArray payload;
    stream >> payload;

    qDebug() << "First byte" << (unsigned char)payload[0];
    if(static_cast<uint>(payload.size()) != _expected_bulk_size) {
      throw QRunTimeError("Incorrect bulk user message length, got " +
          QString::number(payload.size()) + " expected " +
          QString::number(_expected_bulk_size));
    }

    _user_messages[idx] = payload;

    _received_user_messages++;
    if(HasAllDataMessages()) {
      FinishPhase();
    }
  }

  void TolerantBulkRound::HandleServerBulkData(QDataStream &stream, const Id &from)
  {
    qDebug() << _user_idx << GetLocalId().ToString() <<
      ": received bulk server data from " << GetGroup().GetIndex(from) << from.ToString();

    if(_state != DataSharing && _state != BlameWaitingForShuffle) {
      throw QRunTimeError("Received a misordered ServerBulkData message");
    }

    uint idx = GetGroup().GetIndex(from);
    if(!_server_messages[idx].isEmpty()) {
      throw QRunTimeError("Already have bulk server data.");
    }

    QByteArray payload;
    stream >> payload;

    if(static_cast<uint>(payload.size()) != _expected_bulk_size) {
      throw QRunTimeError("Incorrect bulk server message length, got " +
          QString::number(payload.size()) + " expected " +
          QString::number(_expected_bulk_size));
    }

    _server_messages[idx] = payload;

    qDebug() << "Received server" << _received_server_messages; 

    _received_server_messages++;
    if(HasAllDataMessages()) {
      FinishPhase();
    }
  }

  bool TolerantBulkRound::HasAllDataMessages() 
  {
    return (_received_user_messages == static_cast<uint>(GetGroup().Count()) &&
        _received_server_messages == static_cast<uint>(GetGroup().GetSubgroup().Count()));
  }

  void TolerantBulkRound::ProcessMessages()
  {
    uint size = GetGroup().Count();

    QByteArray cleartext(_expected_bulk_size, 0);

    for(int idx=0; idx<_user_messages.count(); idx++) {
      Xor(cleartext, cleartext, _user_messages[idx]);
    }

    for(int idx=0; idx<_server_messages.count(); idx++) {
      Xor(cleartext, cleartext, _server_messages[idx]);
    }

    SaveMessagesToHistory();

    uint msg_idx = 0;
    for(uint member_idx = 0; member_idx < size; member_idx++) {
      int length = _message_lengths[member_idx] + _header_lengths[member_idx];
      QByteArray tcleartext = cleartext.mid(msg_idx, length);
      QByteArray msg = ProcessMessage(tcleartext, member_idx);
      msg_idx += length;
      
      if(!msg.isEmpty()) {
        PushData(msg, this);
      }
    }
  }

  QByteArray TolerantBulkRound::ProcessMessage(const QByteArray &slot_string, uint member_idx)
  {
    QSharedPointer<AsymmetricKey> verification_key(_slot_signing_keys[member_idx]);
    uint vkey_size = verification_key->GetKeySize() / 8;

    // Remove message randomization
    QByteArray cleartext = _message_randomizer.Derandomize(slot_string);

    QByteArray base = cleartext.mid(0, cleartext.size() - vkey_size - 1);
    QByteArray sig = cleartext.mid(cleartext.size() - vkey_size - 1, vkey_size);
    // Shuffle byte is the last byte in the randomized string
    char shuffle_byte = cleartext[cleartext.size()-1];

    bool is_my_message = _anon_signing_key->VerifyKey(*verification_key);

    qDebug() << "Slot" << slot_string.count() << "Clear" << cleartext.count() <<"base"<<base.count();

    // Verify the signature before doing anything
    if(verification_key->Verify(base, sig)) {
      if(is_my_message) {
        _looking_for_evidence = NotLookingForEvidence;
      }

      uint found_phase = Serialization::ReadInt(cleartext, 0);
      if(found_phase != _phase) {
        qWarning() << "Received a message for an invalid phase:" << found_phase;
        return QByteArray();
      }

      // Mark message slot as uncorrupted
      _message_history.MarkSlotBlameFinished(member_idx);
      _user_alibi_data.MarkSlotBlameFinished(member_idx);
      if(_is_server) {
        _server_alibi_data.MarkSlotBlameFinished(member_idx);
      }

      _message_lengths[member_idx] = Serialization::ReadInt(cleartext, 4);

      return base.mid(8);
    } 

    // What to do if sig doesn't verify
    qWarning() << "Verification failed for message of length" << (base.size()-8) << "for slot owner" << member_idx;

    qDebug() << "Marking slot as corrupted";
    _message_history.MarkSlotCorrupted(member_idx);
    _user_alibi_data.MarkSlotCorrupted(member_idx);
    if(_is_server) {
      _server_alibi_data.MarkSlotCorrupted(member_idx);
    }

    qDebug() << "not changing message length of" << _message_lengths[member_idx];
    if(is_my_message) {
      if(_looking_for_evidence == FoundEvidence) {
        qDebug() << "Trying to trigger blame";
      } else {
        qDebug() << "My message was corrupted! Fishing for blame";

        if(SearchForEvidence(_last_msg, slot_string)) {
          qDebug() << "Found evidence in index" << _accusation.GetByteIndex() 
            << "with bit index" << _accusation.GetBitIndex();
          _looking_for_evidence = FoundEvidence;
        } else {
          qDebug() << "no evidence found";
          _looking_for_evidence = LookingForEvidence;
        }
      }
    }

    if(shuffle_byte) {
      qDebug() << "Got shuffle byte, going to accusation shuffle!";
      _corrupted_slots.insert(member_idx);
      _state = BlameWaitingForShuffle;
    } else {
      qDebug() << "No shuffle byte, ignoring invalid message.";
    }
    
    return QByteArray();
  }

  QByteArray TolerantBulkRound::GenerateMyCleartextMessage()
  {

    if(_looking_for_evidence == NotLookingForEvidence) {
      QPair<QByteArray, bool> pair = GetData(4096);

      const QByteArray cur_msg = _next_msg;
      _next_msg = pair.first;

      QByteArray cleartext(8, 0);
      Serialization::WriteInt(_phase, cleartext, 0);
      Serialization::WriteInt(_next_msg.size(), cleartext, 4);
      cleartext.append(cur_msg);

      QByteArray sig = _anon_signing_key->Sign(cleartext);

      // AHHHHHH SCREW UP THE SIG
      /*
      if(_user_idx == 2) {
        qDebug() << "SCREWING UP THE SIGNATURE!";
        sig[0] = ~sig[0];
      }
      */

      cleartext.append(sig);

      /* The shuffle byte */
      cleartext.append('\0');
      _last_msg_cleartext = cleartext;
      
      QByteArray randomized = _message_randomizer.Randomize(cleartext);
      _last_msg = randomized;

      qDebug() << "RANDOMIZED:" << randomized.count();
      return randomized;

    } else if(_looking_for_evidence == LookingForEvidence) {

      /* Repeat a re-randomized version of the
         last message until you find evidence */
      QByteArray randomized = _message_randomizer.Randomize(_last_msg_cleartext);

      qDebug() << "RANDOMIZED:" << randomized.count();
      return randomized;

    } else if(_looking_for_evidence == FoundEvidence) {
      /* Send random bytes to initiate a shuffle */ 
      QSharedPointer<Dissent::Utils::Random> rand(_crypto_lib->GetRandomNumberGenerator());

      QByteArray msg(_last_msg_cleartext.count(), 0);
      rand->GenerateBlock(msg);

      return _message_randomizer.Randomize(msg);

    } else {
      qFatal("Should never reach here!");
      return QByteArray();
    }
  }

  QByteArray TolerantBulkRound::GenerateUserXorMessage()
  {
    QByteArray msg;
    uint size = static_cast<uint>(_slot_signing_keys.size());

    _server_alibi_data.StorePhaseRngByteIndex(_rngs_with_servers[0]->BytesGenerated());

    /* For each slot */
    for(uint idx = 0; idx < size; idx++) {
      uint length = _message_lengths[idx] + _header_lengths[idx];
      QByteArray slot_msg(length, 0);
      qDebug() << "=> STORE BYTES Phase" << _phase << " Slot" << idx << "Bytes=" << _rngs_with_servers[0]->BytesGenerated();

      /* For each server, XOR that server's pad with the empty message */
      for(int server_idx = 0; server_idx < _rngs_with_servers.count(); server_idx++) {
        QByteArray server_pad(length, 0);
        qDebug() << "Bytes generated with server" << server_idx << "=" << _rngs_with_servers[server_idx]->BytesGenerated();

        _rngs_with_servers[server_idx]->GenerateBlock(server_pad);
        qDebug() << "Bytes[0]" << (unsigned char)server_pad[0];

        // AHHH BIT FLIP
        // Tweak bit of some guy's message
       /* 
        if(idx == 1 && server_idx == 0 && _user_idx == 2) {
          qDebug() << "AHHHHHHHHHHHHH FLIPPING BIT from" << 
            (unsigned char)server_pad[0] << "TO" << (unsigned char)(server_pad[0]^1);
          server_pad[0] = (server_pad[0] ^ 1);  
        }
        */
        
       
        qDebug() << "user ciphertext for slot" << idx << "server" 
          << server_idx << "starts with" << (unsigned char)server_pad[0];
        _user_alibi_data.StoreMessage(_phase, idx, server_idx, server_pad);
        Xor(slot_msg, slot_msg, server_pad);
      }
      qDebug() << "slot" << idx << "message starts with" << (unsigned char)slot_msg[0];

      /* This is my slot */
      if(idx == _my_idx) {
        QByteArray my_msg = GenerateMyCleartextMessage();
        Xor(slot_msg, slot_msg, my_msg);
      }

      // Tweak byte of some guy's message
      // AHHHH BIT FLIP
      /*
      if(idx == 1 && _user_idx == 2) {
        qDebug() << "AHHHHHHHHHHHHH FLIPPING BIT from" << (unsigned char)slot_msg[0] << "TO" << (unsigned char)(slot_msg[0]^1);
        slot_msg[0] = (slot_msg[0] ^ 1);  
      }
      */

      msg.append(slot_msg);
      qDebug() << "XOR length" << msg.count();
    }

    return msg;
  }

  QByteArray TolerantBulkRound::GenerateServerXorMessage()
  {
    QByteArray msg;
    uint size = static_cast<uint>(_slot_signing_keys.size());

    _server_alibi_data.StorePhaseRngByteIndex(_rngs_with_users[0]->BytesGenerated());

    /* For each slot */
    for(uint idx = 0; idx < size; idx++) {
      uint length = _message_lengths[idx] + _header_lengths[idx];
      QByteArray slot_msg(length, 0);

      /* For each user, XOR that users pad with the empty message */
      for(int user_idx = 0; user_idx < _rngs_with_users.count(); user_idx++) {
        QByteArray user_pad(length, 0);
        _rngs_with_users[user_idx]->GenerateBlock(user_pad);

        // AHHH FLIP BIT
        /*
        if(idx == 0 && user_idx == 0 && _user_idx == 1) {
          qDebug() << "AHHHHHHHHHHHHH FLIPPING BIT from" << 
            (unsigned char)user_pad[1] << "TO" << (unsigned char)(user_pad[1]^1);
          user_pad[1] = (user_pad[1] ^ 1);  
        }
        */

        _server_alibi_data.StoreMessage(_phase, idx, user_idx, user_pad);
        Xor(slot_msg, slot_msg, user_pad);
      }
      
      msg.append(slot_msg);
      qDebug() << "XOR length" << msg.count();
    }

    return msg;
  }

  void TolerantBulkRound::SaveMessagesToHistory()
  {
    uint offset = 0;
    for(int slot = 0; slot < GetGroup().Count(); slot++) {
      int slot_length = _message_lengths[slot] + _header_lengths[slot];

      for(int user_idx=0; user_idx<_user_messages.count(); user_idx++) {
        _message_history.AddUserMessage(_phase, slot, user_idx, _user_messages[user_idx].mid(offset, slot_length));
      }

      for(int server_idx=0; server_idx<_server_messages.count(); server_idx++) {
        _message_history.AddServerMessage(_phase, slot, server_idx, _server_messages[server_idx].mid(offset, slot_length));
      }

      offset += slot_length;
    }
  }

  bool TolerantBulkRound::SearchForEvidence(const QByteArray& sent_msg, const QByteArray& recvd_msg)
  {
    qDebug() << "Message lengths sent" << sent_msg.size() << "r" << recvd_msg.size();
    Q_ASSERT(sent_msg.size() == recvd_msg.size());

    char c, d;
    for(int i=0; i<sent_msg.count(); i++) {
      c = sent_msg[i];
      d = recvd_msg[i];
      qDebug() << "Sent:" << (unsigned char)c << "Got:" << (unsigned char)d << (c == d ? "" : "<===");
    }

    for(int i=0; i<sent_msg.count(); i++) {
      c = sent_msg[i];
      d = recvd_msg[i];

      /* Bitmask of zeros in c that were changed to 
         ones in d */
      char zeros_flipped_to_ones = ((c ^ d) & (~c));
      if(zeros_flipped_to_ones) {
        return _accusation.SetData(_phase, i, zeros_flipped_to_ones);
      }
    }
    return false;
  }

  void TolerantBulkRound::ResetBlameData()
  {
    _acc_data.clear();
    _user_alibis.clear();
    _server_alibis.clear();
    _user_alibis_received = 0;
    _server_alibis_received = 0;

    _conflicts.clear();
    _user_proofs.clear();
    _server_proofs.clear();
    _user_proofs_received = 0;
    _server_proofs_received = 0;
  }

  void TolerantBulkRound::RunBlameShuffle()
  {
    ResetBlameData();

    QSharedPointer<Network> net(GetNetwork()->Clone());

    QVariantMap headers = net->GetHeaders();
    headers["round"] = Header_BlameShuffle;

    net->SetHeaders(headers);

    QScopedPointer<Hash> hashalgo(_crypto_lib->GetHashAlgorithm());
    QByteArray rid = GetRoundId().GetByteArray();
    rid.append("BLAME");
    rid.append(_phase);
    Id sr_id(hashalgo->ComputeHash(rid));

    _blame_shuffle_round = QSharedPointer<Round>(_create_shuffle(GetGroup(), 
          GetCredentials(), sr_id, net, _get_blame_shuffle_data));
    _blame_shuffle_round->SetSink(&_blame_shuffle_sink);

    QObject::connect(_blame_shuffle_round.data(), SIGNAL(Finished()),
        this, SLOT(BlameShuffleFinished()));

    qDebug() << "Starting blame shuffle with rid" << sr_id.ToString();
    _blame_shuffle_round->Start();
  }

  QPair<QByteArray, bool> TolerantBulkRound::GetBlameShuffleData(int)
  {
    if(_looking_for_evidence == FoundEvidence && _accusation.IsInitialized()) {
      QByteArray acc = _accusation.ToByteArray();
      QByteArray sig = _anon_signing_key->Sign(acc);
      QByteArray out;
      out.append(acc);
      out.append(sig);
      
      return QPair<QByteArray, bool>(out, false);
    } else {
      return QPair<QByteArray, bool>(QByteArray(), false); 
    }
  }

  void TolerantBulkRound::SendUserAlibis(QMap<int, Accusation> &map)
  {
    _expected_alibi_qty = map.count();

    QByteArray alibi_bytes;
    for(QMap<int, Accusation>::const_iterator i=map.constBegin(); i!=map.constEnd(); ++i) {
      Accusation acc = i.value();
      QByteArray al = _user_alibi_data.GetAlibiBytes(i.key(), acc);
      alibi_bytes.append(al);
    }

    QByteArray packet;
    QDataStream stream(&packet, QIODevice::WriteOnly);
    stream << MessageType_UserAlibiData << GetRoundId() << _phase << alibi_bytes;
    VerifiableBroadcast(packet);
  }

  void TolerantBulkRound::SendServerAlibis(QMap<int, Accusation> &map)
  {
    _expected_alibi_qty = map.count();

    QByteArray alibi_bytes;
    for(QMap<int, Accusation>::const_iterator i=map.constBegin(); i!=map.constEnd(); ++i) {
      Accusation acc = i.value();
      QByteArray al = _server_alibi_data.GetAlibiBytes(i.key(), acc);
      alibi_bytes.append(al);
    }

    QByteArray packet;
    QDataStream stream(&packet, QIODevice::WriteOnly);
    stream << MessageType_ServerAlibiData << GetRoundId() << _phase << alibi_bytes;
    VerifiableBroadcast(packet);
  }

  void TolerantBulkRound::HandleUserAlibiData(QDataStream &stream, const Id &from)
  {
    qDebug() << _user_idx << GetLocalId().ToString() <<
      ": received user alibi data from " << GetGroup().GetIndex(from) << from.ToString();

    if(!_user_alibis.size()) {
      qDebug() << "Resizing user alibi vector";
      _user_alibis.resize(GetGroup().Count());
    }

    if(_state != BlameExchangingAlibis) {
      throw QRunTimeError("Received a misordered user alibi message");
    }

    uint idx = GetGroup().GetIndex(from);
    if(!_user_alibis[idx].isEmpty()) {
      throw QRunTimeError("Already have user alibi.");
    }

    QByteArray payload;
    stream >> payload;

    uint total_length = AlibiData::ExpectedAlibiLength(GetGroup().GetSubgroup().Count()) * _expected_alibi_qty;
    if(static_cast<uint>(payload.size()) != total_length) {
      throw QRunTimeError("Incorrect user alibi message length, got " +
          QString::number(payload.size()) + " expected " +
          QString::number(total_length));
    }

    _user_alibis_received++;
    _user_alibis[idx] = payload;

    qDebug() << "Received user alibi sets" << _user_alibis.count() << "len:" << payload.count() << "," << _user_alibis[idx].count(); 
    if(HasAllAlibis()) {
      qDebug() << "Starting alibi analysis!";
      RunAlibiAnalysis();
      return;
    }
  }

  void TolerantBulkRound::HandleServerAlibiData(QDataStream &stream, const Id &from)
  {
    qDebug() << _user_idx << GetLocalId().ToString() <<
      ": received server alibi data from " << GetGroup().GetIndex(from) << from.ToString();

    if(!_server_alibis.size()) {
      _server_alibis.resize(GetGroup().GetSubgroup().Count());
    }

    if(_state != BlameExchangingAlibis) {
      throw QRunTimeError("Received a misordered server alibi message");
    }

    uint idx = GetGroup().GetIndex(from);
    if(!_server_alibis[idx].isEmpty()) {
      throw QRunTimeError("Already have server alibi.");
    }


    QByteArray payload;
    stream >> payload;

    uint total_length = AlibiData::ExpectedAlibiLength(GetGroup().Count()) * _expected_alibi_qty;
    if(static_cast<uint>(payload.size()) != total_length) {
      throw QRunTimeError("Incorrect server alibi message length, got " +
          QString::number(payload.size()) + " expected " +
          QString::number(total_length));
    }

    _server_alibis_received++;
    _server_alibis[idx] = payload;

    qDebug() << "Received server alibi sets" << _server_alibis.count(); 
    if(HasAllAlibis()) {
      qDebug() << "Ready to start blame!";
      RunAlibiAnalysis();
      return;
    }
  }

  bool TolerantBulkRound::HasAllAlibis() 
  {
    return (_user_alibis_received == static_cast<uint>(GetGroup().Count()) &&
        _server_alibis_received == static_cast<uint>(GetGroup().GetSubgroup().Count()));
  }

  void TolerantBulkRound::RunAlibiAnalysis()
  {
    const int old_bad_members = _bad_members.count();
    const int old_bad_slots = _bad_slots.count();
    const uint members = GetGroup().Count();
    const uint user_alibi_length = AlibiData::ExpectedAlibiLength(GetGroup().GetSubgroup().Count());
    const uint server_alibi_length = AlibiData::ExpectedAlibiLength(members);

    uint count = 0;
    for(QMap<int, Accusation>::iterator i=_acc_data.begin(); i != _acc_data.end(); ++i) {
      const uint slot_idx = i.key();

      BlameMatrix matrix(GetGroup().Count(), GetGroup().GetSubgroup().Count());
     
      // For each user...
      for(uint user_idx=0; user_idx<static_cast<uint>(GetGroup().Count()); user_idx++) {
        // Add user alibi bitmasks
        QByteArray alibi = _user_alibis[user_idx].mid(count*user_alibi_length, user_alibi_length);
        qDebug() << "Alibi has length" << alibi.count();
        QBitArray bits = AlibiData::AlibiBitsFromBytes(alibi, 0, GetGroup().GetSubgroup().Count());
        matrix.AddUserAlibi(user_idx, bits);

        // Add the bit that the user actually sent in the corrupted slot
        bool user_bit = _message_history.GetUserOutputBit(slot_idx, user_idx, i.value());
        matrix.AddUserOutputBit(user_idx, user_bit);
      }
  
      // For each server...
      for(uint server_idx=0; server_idx<static_cast<uint>(GetGroup().GetSubgroup().Count()); server_idx++) {
        // Add server alibi bitmasks
        QByteArray alibi = _server_alibis[server_idx].mid(count*server_alibi_length, server_alibi_length);
        QBitArray bits = AlibiData::AlibiBitsFromBytes(alibi, 0, members);
        matrix.AddServerAlibi(server_idx, bits);

        // Add the bit that the server actually sent in the corrupted slot
        bool server_bit = _message_history.GetServerOutputBit(slot_idx, server_idx, i.value());
        matrix.AddServerOutputBit(server_idx, server_bit);
      }

      QVector<int> bad_users = matrix.GetBadUsers();
      if(bad_users.count()) {
        qWarning() << "Found bad users" << bad_users;
        AddBadMembers(bad_users);
      }

      QVector<int> bad_servers = matrix.GetBadServers();
      if(bad_servers.count()) {
        qWarning() << "Found bad servers" << bad_servers;
        AddBadMembers(bad_servers);
      }

      qWarning() << "So far, have found" << GetBadMembers().count() << "bad member(s)";

      QList<Conflict> acc_conflicts = matrix.GetConflicts(slot_idx);
      _conflicts += acc_conflicts;

      if(!bad_users.count() && !bad_servers.count() && !acc_conflicts.count()) {
        qWarning("No bad members found after investigating alibi data, blaming anonymous slot owner");
        _bad_slots.insert(slot_idx);
      }

      count++;
    }

    if(_conflicts.count()) {
      qWarning() << "Found conflicts" << _conflicts.count();
      ProcessConflicts();
      return;
    } 

    if(old_bad_members != _bad_members.count()) {
      // Blame finished
      qWarning("Blamed member, STOPPING");
      return;
    }

    if(old_bad_slots != _bad_slots.count()) {
      // Blame finished
      qWarning("Blamed anonymous slot owner, STOPPING");
      return;
    }

    qFatal("Should never get here! Blame ran but no bad member found.");
  }

  void TolerantBulkRound::ProcessConflicts()
  {
    QByteArray proof_messages;
    for(int i=0; i<_conflicts.count(); i++) {
      uint user_idx = _conflicts[i].GetUserIndex();
      uint server_idx = _conflicts[i].GetServerIndex();

      if(user_idx == _user_idx) {
        qDebug() << "User" << _user_idx << "needs to send proof";
        SendUserProof(i, server_idx);
      }

      if(_is_server && server_idx == _server_idx) {
        qDebug() << "Server" << _server_idx << "needs to send proof";
        SendServerProof(i, user_idx);
      }
    }
  }

  void TolerantBulkRound::HandleUserProofData(QDataStream &stream, const Id &from)
  {
    qDebug() << _user_idx << GetLocalId().ToString() <<
      ": received user proof data from " << GetGroup().GetIndex(from) << from.ToString();

    if(_state != BlameExchangingAlibis) {
      throw QRunTimeError("Received a misordered user proof message");
    }

    int conflict_idx;
    QByteArray payload;
    stream >> conflict_idx >> payload;
    qDebug() << "Conflict id" << conflict_idx;

    if(conflict_idx > (GetGroup().Count() * GetGroup().GetSubgroup().Count())) {
      throw QRunTimeError("Conflict index out of range");
    }
    
    if((conflict_idx+1) > _user_proofs.size()) {
      qDebug() << "Resizing user proof vector";
      _user_proofs.resize(conflict_idx+1);
    }

    if(!_user_proofs[conflict_idx].isEmpty()) {
      throw QRunTimeError("Already have user proof.");
    }

    if(_conflicts[conflict_idx].GetUserIndex() != static_cast<uint>(GetGroup().GetIndex(from))) {
      throw QRunTimeError("Got spoofed proof message!");
    }

    _user_proofs_received++;
    _user_proofs[conflict_idx] = payload;

    qDebug() << "Received user proofs" << _user_proofs.count() << "len:" << payload.count();
    if(HasAllProofs()) {
      qDebug() << "Starting proof analysis!";
      RunProofAnalysis();
      return;
    }
  }

  void TolerantBulkRound::HandleServerProofData(QDataStream &stream, const Id &from)
  {
    qDebug() << _user_idx << GetLocalId().ToString() <<
      ": received server proof data from " << GetGroup().GetIndex(from) << from.ToString();

    if(_state != BlameExchangingAlibis) {
      throw QRunTimeError("Received a misordered server proof message");
    }

    int conflict_idx;
    QByteArray payload;
    stream >> conflict_idx >> payload;
    qDebug() << "Conflict id" << conflict_idx;

    if(conflict_idx > (GetGroup().Count() * GetGroup().GetSubgroup().Count())) {
      throw QRunTimeError("Conflict index out of range");
    }
    
    if((conflict_idx+1) > _server_proofs.size()) {
      qDebug() << "Resizing server proof vector";
      _server_proofs.resize(conflict_idx+1);
    }

    if(!_server_proofs[conflict_idx].isEmpty()) {
      throw QRunTimeError("Already have server proof.");
    }

    if(_conflicts[conflict_idx].GetServerIndex() != static_cast<uint>(GetGroup().GetIndex(from))) {
      throw QRunTimeError("Got spoofed server proof message!");
    }

    _server_proofs_received++;
    _server_proofs[conflict_idx] = payload;

    qDebug() << "Received server proofs" << _server_proofs.count() << "len:" << payload.count();
    if(HasAllProofs()) {
      qDebug() << "Starting proof analysis!";
      RunProofAnalysis();
      return;
    }
  }

  bool TolerantBulkRound::HasAllProofs() 
  {
    return (_user_proofs_received == static_cast<uint>(_conflicts.count()) &&
        _server_proofs_received == static_cast<uint>(_conflicts.count()));
  }

  void TolerantBulkRound::RunProofAnalysis()
  {
    qDebug() << "Starting proof analysis";
    for(int i=0; i<_conflicts.count(); i++) {
      uint slot_idx = _conflicts[i].GetSlotIndex();
      uint user_idx = _conflicts[i].GetUserIndex();
      uint server_idx = _conflicts[i].GetServerIndex();

      if(user_idx == server_idx) {
        _bad_members.insert(user_idx);
        qWarning() << "User and server ID cannot be the same! Member" << user_idx << "is bad";
        continue;
      }

      QByteArray user_pub_key = _user_public_dh_keys[user_idx];
      QByteArray server_pub_key = _server_public_dh_keys[server_idx];

      QByteArray user_proof = _user_proofs[i];
      qDebug() << "Proof:" << user_proof.toHex().constData();
      qDebug() << "Pub key:" << user_pub_key.toHex().constData();
      qDebug() << "Server key:" << server_pub_key.toHex().constData();

      QByteArray user_valid = _user_dh_key->VerifySharedSecret(user_pub_key, server_pub_key, user_proof);
      if(!user_valid.count()) {
        qWarning() << "User" << user_idx << "send bad proof";
        _bad_members.insert(user_idx);
      }

      QByteArray server_proof = _server_proofs[i];
      QByteArray server_valid = _user_dh_key->VerifySharedSecret(server_pub_key, user_pub_key, server_proof);
      if(!server_valid.count()) {
        qWarning() << "Server" << server_idx << "send bad proof";
        _bad_members.insert(server_idx);
      }

      if(!user_valid.count() || !server_valid.count()) {
          // We blamed one person, so we can stop now
          continue;
      }

      qDebug() << "Run RNGs to figure out which bit was right";
      if(user_valid != server_valid) {
        qFatal("Proofs are both valid but generate different shared secrets!");
      }

      // Check which bit was generated correctly
      qDebug() << "ACC" << _acc_data[slot_idx].ToString();
      const bool expected_bit = GetExpectedBit(slot_idx, _acc_data[slot_idx], user_valid);
      const bool user_bit = _conflicts[i].GetUserBit();
      const bool server_bit = _conflicts[i].GetServerBit();

      qDebug() << "Bit check || Expected: " << expected_bit << "Server:" << server_bit << "User:" << user_bit;

      if(expected_bit != server_bit) {
        _bad_members.insert(server_idx);
        qDebug() << "Blaming server" << server_idx;
        qWarning("Server revealed correct secret but sent bad bit!");
      }

      if(expected_bit != user_bit) {
        _bad_members.insert(user_idx);
        qDebug() << "Blaming user" << user_idx;
        qWarning("User revealed correct secret but sent bad bit!");
      }

      if((expected_bit == server_bit) && (server_bit == user_bit)) {
        qFatal("Should never reach here -- server, user, and expected bits all agree. No one to blame.");
      }
    }

    qDebug() << "Done with proof analysis";
    return;
  }

  void TolerantBulkRound::SendUserProof(int conflict_idx, uint server_idx)
  {
    QByteArray proof = _user_dh_key->ProveSharedSecret(_server_public_dh_keys[server_idx]);
    qDebug() << "Sending user proof len" << proof.count();
    qDebug() << "Proof:" << proof.toHex().constData();

    QByteArray packet;
    QDataStream stream(&packet, QIODevice::WriteOnly);
    stream << MessageType_UserProofData << GetRoundId() << _phase << conflict_idx << proof;
    VerifiableBroadcast(packet);
  }

  void TolerantBulkRound::SendServerProof(int conflict_idx, uint user_idx)
  {
    QByteArray proof = _server_dh_key->ProveSharedSecret(_user_public_dh_keys[user_idx]);

    QByteArray packet;
    QDataStream stream(&packet, QIODevice::WriteOnly);
    stream << MessageType_ServerProofData << GetRoundId() << _phase << conflict_idx << proof;
    VerifiableBroadcast(packet);
  }

  bool TolerantBulkRound::GetExpectedBit(uint slot_idx, Accusation &acc, QByteArray &seed)
  {
    // prev_bytes = number of bytes generated in previous phases
    const uint prev_bytes = _user_alibi_data.GetSlotRngByteOffset(acc.GetPhase(), slot_idx);

    // slot_length = number of bytes in the corrupted slot 
    const uint slot_length = acc.GetByteIndex();

    const uint total_bytes = prev_bytes + slot_length;

    QByteArray bytes(total_bytes+1, 0);

    QSharedPointer<Random> rand(_crypto_lib->GetRandomNumberGenerator(seed));

    rand->GenerateBlock(bytes);

    const char expected_byte = bytes[total_bytes];

    qDebug() << "Getting expected bit from byte" << prev_bytes
      << "+" << slot_length << ", bit" << (int)acc.GetBitIndex() 
      << "[Byte" << (unsigned char) expected_byte << "]" 
      << "slot idx" << slot_idx;
    
    return expected_byte & (1 << acc.GetBitIndex());
  }

  void TolerantBulkRound::PrepForNextPhase()
  {
    uint group_size = static_cast<uint>(GetGroup().Count());
    _user_messages = QVector<QByteArray>(group_size);
    _received_user_messages = 0;

    _server_messages = QVector<QByteArray>(GetGroup().GetSubgroup().Count());
    _received_server_messages = 0;

    _expected_bulk_size = 0;
    for(uint idx = 0; idx < group_size; idx++) {
      _expected_bulk_size += _header_lengths[idx] + _message_lengths[idx];
    }

    qDebug() << "Clearing old alibi data";
    _message_history.NextPhase();
    _user_alibi_data.NextPhase();
    if(_is_server) {
      _server_alibi_data.NextPhase();
    }

    _corrupted_slots.clear();
  }

  void TolerantBulkRound::NextPhase()
  {
    qDebug() << "--";
    qDebug() << "-- NEXT PHASE :" << _phase;
    qDebug() << "--";

    QByteArray user_xor_msg = GenerateUserXorMessage();
    QByteArray user_packet;
    QDataStream user_stream(&user_packet, QIODevice::WriteOnly);
    user_stream << MessageType_UserBulkData << GetRoundId() << _phase << user_xor_msg;
    VerifiableBroadcast(user_packet);

    if(_is_server) {
      QByteArray server_xor_msg = GenerateServerXorMessage();
      QByteArray server_packet;
      QDataStream server_stream(&server_packet, QIODevice::WriteOnly);
      server_stream << MessageType_ServerBulkData << GetRoundId() << _phase << server_xor_msg;
      VerifiableBroadcast(server_packet);
    }
  }

  void TolerantBulkRound::FinishPhase() 
  {
    if(_state == BlameWaitingForShuffle) {
      qWarning("Entering blame shuffle");
      RunBlameShuffle();
      return;
    } else {
      ProcessMessages();
      if(_state == BlameWaitingForShuffle) {
        RunBlameShuffle();
        return;
      }
      PrepForNextPhase();
      _phase++;

      uint count = static_cast<uint>(_offline_log.Count());
      for(uint idx = 0; idx < count; idx++) {
        QPair<QByteArray, Id> entry = _offline_log.At(idx);
        ProcessData(entry.first, entry.second);
      }

      _offline_log.Clear();

      NextPhase();
    }
  }

  void TolerantBulkRound::KeyShuffleFinished()
  {
    if(!_key_shuffle_round->Successful()) {
      AddBadMembers(_key_shuffle_round->GetBadMembers());
      _state = Finished;
      Stop("ShuffleRound failed");
      return;
    }

    if(_key_shuffle_sink.Count() != GetGroup().Count()) {
      qWarning() << "Did not receive a descriptor from everyone.";
    }

    uint count = static_cast<uint>(_key_shuffle_sink.Count());
    for(uint idx = 0; idx < count; idx++) {
      QPair<QByteArray, ISender *> pair(_key_shuffle_sink.At(idx));
      _slot_signing_keys.append(ParseSigningKey(pair.first));
      
      // Header fields in every slot
      _header_lengths.append(1  // shuffle byte
          + 4                   // phase
          + 4                   // message length
          + (_slot_signing_keys.last()->GetKeySize() / 8) // signature
          + _message_randomizer.GetHeaderLength() // randomizer seed
        );

      // Everyone starts out with a zero-length message
      _message_lengths.append(0);

      if(_key_shuffle_data == pair.first) {
        _my_idx = idx;
      }
    }

    PrepForNextPhase();

    NextPhase();
    // Avoid a race condition of phase 1 messages arriving before completing
    // the full transition into phase 0 / DataSharing
    _state = DataSharing;

    count = static_cast<uint>(_offline_log.Count());
    for(uint idx = 0; idx < count; idx++) {
      QPair<QByteArray, Id> entry = _offline_log.At(idx);
      ProcessData(entry.first, entry.second);
    }

    _offline_log.Clear();
  }

  void TolerantBulkRound::BlameShuffleFinished()
  {
    qDebug() << "Finished blame/accusation shuffle";
    if(!_blame_shuffle_round->Successful()) {
      AddBadMembers(_blame_shuffle_round->GetBadMembers());
      _state = Finished;
      Stop("Blame ShuffleRound Failed");
      return;
    } 
  
    qDebug() << "Got" << _blame_shuffle_sink.Count() << "accusations";

    int count = _blame_shuffle_sink.Count();
    QList<QPair<int,char> > accusations;

    // For each accusation
    for(int idx =0; idx<count; idx++) {
      QByteArray msg = _blame_shuffle_sink.At(idx).first;
      QPair<int, char> pair;
    
      QByteArray acc_bytes = msg.mid(0, Accusation::AccusationByteLength);
      QByteArray sig_bytes = msg.mid(Accusation::AccusationByteLength);

      int acc_owner;
      bool verified = false;

      for(int i=0; i<_slot_signing_keys.count(); i++) {
        if(_slot_signing_keys[i]->Verify(acc_bytes, sig_bytes)) {
          verified = true;
          acc_owner = i; 
          break;
        }
      }

      if(verified) {
        Accusation acc;
        if(acc.FromByteArray(acc_bytes)) {
          qDebug() << "Got accusation from slot owner" << acc_owner << ":" << acc.ToString();

          _message_history.MarkSlotBlameFinished(acc_owner);
          _user_alibi_data.MarkSlotBlameFinished(acc_owner);
          if(_is_server) {
            _server_alibi_data.MarkSlotBlameFinished(acc_owner);
          }

          _acc_data.insert(acc_owner, acc);
        } else {
          qWarning() << "Ignoring invalid accusation of length" << acc_bytes.size() << 
              "from owner of slot" << acc_owner;
        }
      } else {
        qWarning("Ignoring accusation with bad signature");
      }
    }

    if(_acc_data.count()) {
      _state = BlameExchangingAlibis;
      SendUserAlibis(_acc_data); 
      if(_is_server) {
        SendServerAlibis(_acc_data);
      }
    } else {
      qWarning() << "No valid accusations. Blaming anonymous slot owners:" << _corrupted_slots;
      _state = DataSharing;
    }
  }
}
}
}
