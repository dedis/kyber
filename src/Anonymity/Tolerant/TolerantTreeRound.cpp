#include "Anonymity/BulkRound.hpp"
#include "Anonymity/ShuffleRound.hpp"
#include "Connections/IOverlaySender.hpp"
#include "Connections/Network.hpp"
#include "Crypto/DiffieHellman.hpp"
#include "Crypto/Hash.hpp"
#include "Crypto/Library.hpp"
#include "Crypto/Serialization.hpp"
#include "Messaging/Request.hpp"
#include "Utils/QRunTimeError.hpp"
#include "Utils/Random.hpp"
#include "Utils/Serialization.hpp"

#include "TolerantTreeRound.hpp"

using Dissent::Connections::Connection;
using Dissent::Crypto::CryptoFactory;
using Dissent::Crypto::DiffieHellman;
using Dissent::Crypto::Library;
using Dissent::Utils::QRunTimeError;
using Dissent::Utils::Random;
using Dissent::Utils::Serialization;

namespace Dissent {
namespace Anonymity {
namespace Tolerant {
  TolerantTreeRound::TolerantTreeRound(const Group &group,
      const PrivateIdentity &ident, const Id &round_id, QSharedPointer<Network> network,
      GetDataCallback &get_data, CreateRound create_shuffle) :
    Round(group, ident, round_id, network, get_data),
    _is_server(GetGroup().GetSubgroup().Contains(GetLocalId())),
    _is_leader((GetGroup().GetLeader() == GetLocalId())),
    _stop_next(false),
    _secrets_with_servers(GetGroup().GetSubgroup().Count()),
    _rngs_with_servers(GetGroup().GetSubgroup().Count()),
    _get_key_shuffle_data(this, &TolerantTreeRound::GetKeyShuffleData),
    _create_shuffle(create_shuffle),
    _state(State_Offline),
    _crypto_lib(CryptoFactory::GetInstance().GetLibrary()),
    _hash_algo(_crypto_lib->GetHashAlgorithm()),
    _anon_signing_key(_crypto_lib->CreatePrivateKey()),
    _phase(0),
    _server_messages(GetGroup().GetSubgroup().Count()),
    _server_client_lists(GetGroup().GetSubgroup().Count()),
    _server_message_digests(GetGroup().GetSubgroup().Count()),
    _server_final_sigs(GetGroup().GetSubgroup().Count()),
    _message_randomizer(ident.GetDhKey()->GetPrivateComponent()),
    _user_idx(GetGroup().GetIndex(GetLocalId()))
  {
    qDebug() << "LocID" << GetLocalId().ToString() 
      << "LeadID" << GetGroup().GetLeader().ToString();

    QVariantHash headers = GetNetwork()->GetHeaders();
    headers["round"] = Header_Bulk;
    GetNetwork()->SetHeaders(headers);

    // Get shared secrets with servers
    const Group servers = GetGroup().GetSubgroup();
    for(int server_idx=0; server_idx<servers.Count(); server_idx++) {
      QByteArray server_pk = servers.GetPublicDiffieHellman(server_idx);
      QByteArray secret = ident.GetDhKey()->GetSharedSecret(server_pk);

      _secrets_with_servers[server_idx] = secret;
      _rngs_with_servers[server_idx] = QSharedPointer<Random>(_crypto_lib->GetRandomNumberGenerator(secret));
      qDebug() << "RNG with server" << server_idx << "Generated" << _rngs_with_servers[server_idx]->BytesGenerated();
    }

    // Set up shared secrets
    if(_is_server) {
      _secrets_with_users.resize(GetGroup().Count());
      _rngs_with_users.resize(GetGroup().Count());
      _server_idx = GetGroup().GetSubgroup().GetIndex(GetLocalId());

      // Get shared secrets with users
      const Group users = GetGroup();
      for(int user_idx=0; user_idx<users.Count(); user_idx++) {
        QByteArray user_pk = users.GetPublicDiffieHellman(user_idx);
        QByteArray secret = ident.GetDhKey()->GetSharedSecret(user_pk);

        _secrets_with_users[user_idx] = secret;
        _rngs_with_users[user_idx] = QSharedPointer<Random>(_crypto_lib->GetRandomNumberGenerator(secret));
        qDebug() << "RNG with user" << user_idx << "Generated" << _rngs_with_users[user_idx]->BytesGenerated();

        if(static_cast<uint>(user_idx % GetGroup().GetSubgroup().Count()) == _server_idx) {
          _my_users.append(GetGroup().GetId(user_idx));
        }
      }
    }

    // Set up signing key shuffle
    QSharedPointer<Network> net(GetNetwork()->Clone());
    headers["round"] = Header_SigningKeyShuffle;
    net->SetHeaders(headers);

    Id sr_id(_hash_algo->ComputeHash(GetRoundId().GetByteArray()));

    _key_shuffle_round = _create_shuffle(GetGroup(), GetPrivateIdentity(), sr_id,
        net, _get_key_shuffle_data);
    _key_shuffle_round->SetSink(&_key_shuffle_sink);

    QObject::connect(_key_shuffle_round.data(), SIGNAL(Finished()),
        this, SLOT(KeyShuffleFinished()));
  }

  TolerantTreeRound::~TolerantTreeRound() {
    _timer_user_cutoff.Stop();
    _slot_signing_keys.clear();
  }

  void TolerantTreeRound::OnStart()
  {
    ChangeState(State_SigningKeyShuffling);
    _key_shuffle_round->Start();
  }

  void TolerantTreeRound::FoundBadMembers() 
  {
    SetSuccessful(false);
    _offline_log.Clear();
    ChangeState(State_Finished);
    Stop("Found bad group member");
    return;
  }

  void TolerantTreeRound::IncomingData(const Request &notification)
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
    int round = msg.value("round").toInt();
    switch(round) {
      case Header_Bulk:
        ProcessData(id, msg.value("data").toByteArray());
        break;
      case Header_SigningKeyShuffle:
        qDebug() << "Signing key msg";
        _key_shuffle_round->IncomingData(notification);
        break;
      default:
        qWarning() << "Got message with unknown round header:" << round;
    }
  }

  void TolerantTreeRound::HandleDisconnect(const Id &id)
  {
    if(GetGroup().GetSubgroup().Contains(id)) {
      SetInterrupted();
      Stop("Server " + QString(id.ToString() + " disconnected"));
    } else if((_state == State_Offline) || (_state == State_SigningKeyShuffling)) {
      SetInterrupted();
      Stop("Client " + QString(id.ToString() + " disconnected prior to DC-net"));
    } else {
      qDebug() << "Ignoring disconnected client" << id.ToString();
    }
  }

  void TolerantTreeRound::ProcessData(const Id &from, const QByteArray &data)
  {
    _log.Append(data, from);
    try {
      ProcessDataBase(from, data);
    } catch (QRunTimeError &err) {
      qWarning() << _user_idx << GetLocalId().ToString() <<
        "received a message from" << GetGroup().GetIndex(from) << from.ToString() <<
        "in session / round" << GetRoundId().ToString() << "in state" <<
        StateToString(_state) << "causing the following exception: " << err.What();
      _log.Pop();
      return;
    }
  }

  void TolerantTreeRound::ProcessDataBase(const Id &from, const QByteArray &data)
  {
    QByteArray payload;
    if(!Verify(from, data, payload)) {
      throw QRunTimeError("Invalid signature or data");
    }

    if(_state == State_Offline) {
      throw QRunTimeError("Should never receive a message in the bulk"
          " round while offline.");
    }

    QDataStream stream(payload);

    int mtype;
    QByteArray round_id;
    uint phase;
    stream >> mtype >> round_id >> phase;

    MessageType msg_type = static_cast<MessageType>(mtype);

    Id rid(round_id);
    if(rid != GetRoundId()) {
      throw QRunTimeError("Not this round: " + rid.ToString() + " " +
          GetRoundId().ToString());
    }

    // Cache messages for future states in the offline log
    if(!ReadyForMessage(msg_type)) {
      qDebug() << _my_idx << "[" << StateToString(_state) << "] Storing message of type" << MessageTypeToString(msg_type) << _log.Count();
      _log.Pop();
      _offline_log.Append(data, from);
      return;
    }

    if(_phase != phase) {
      throw QRunTimeError("Received a message for phase: " + 
          QString::number(phase) + ", while in phase: " +
          QString::number(_phase));
    }

    switch(msg_type) {
      case MessageType_UserBulkData:
        HandleUserBulkData(stream, from);
        break;
      case MessageType_ServerClientListData:
        HandleServerClientListData(stream, from);
        break;
      case MessageType_ServerCommitData:
        HandleServerCommitData(stream, from);
        break;
      case MessageType_ServerBulkData:
        HandleServerBulkData(payload, stream, from);
        break;
      case MessageType_ServerFinalSig:
        HandleServerFinalSigData(stream, from);
        break;
      case MessageType_ServerFinalData:
        HandleServerFinalData(stream, from);
        break;
      default:
        throw QRunTimeError("Unknown message type");
    }
  }

  QPair<QByteArray, bool> TolerantTreeRound::GetKeyShuffleData(int)
  {
    QByteArray msg;
    QDataStream stream(&msg, QIODevice::WriteOnly);
    QSharedPointer<AsymmetricKey> pub_key(_anon_signing_key->GetPublicKey());
    stream << pub_key;
    _key_shuffle_data = msg;
    return QPair<QByteArray, bool>(msg, false);
  }

  QSharedPointer<TolerantTreeRound::AsymmetricKey> TolerantTreeRound::ParseSigningKey(const QByteArray &bdes)
  {
    QDataStream stream(bdes);
    QSharedPointer<AsymmetricKey> key_pub;
    stream >> key_pub;

    if(!key_pub->IsValid()) {
      qWarning() << "Received an invalid signing key during the shuffle.";
    }

    return key_pub;
  }

  void TolerantTreeRound::SendUserBulkData()
  {
    qDebug() << "In" << ToString() << "starting phase.";

    QByteArray user_xor_msg = GenerateUserXorMessage();
    QByteArray packet;
    QDataStream user_data_stream(&packet, QIODevice::WriteOnly);
    user_data_stream << MessageType_UserBulkData << GetRoundId() << _phase << user_xor_msg;

    ChangeState(_is_server ? State_ServerUserDataReceiving : State_UserFinalDataReceiving);
    VerifiableSendToServer(packet);
  }

  void TolerantTreeRound::HandleUserBulkData(QDataStream &stream, const Id &from)
  {
    qDebug() << _user_idx << GetLocalId().ToString() <<
      ": received bulk user data from " << GetGroup().GetIndex(from) << from.ToString();

    if(!_is_server) {
      throw QRunTimeError("Non-server received a UserBulkData message");
    }

    if(_state != State_ServerUserDataReceiving) {
      throw QRunTimeError("Received a misordered UserBulkData message");
    }

    if(!_my_users.contains(from)) {
      throw QRunTimeError("Server received a UserBulkData message from non-user");
    }

    const int user_idx = GetGroup().GetIndex(from);
    if(_user_messages.contains(user_idx)) {
      throw QRunTimeError("Already have bulk user data.");
    }

    QByteArray payload;
    stream >> payload;

    if(static_cast<uint>(payload.size()) != _expected_bulk_size) {
      throw QRunTimeError("Incorrect bulk user message length, got " +
          QString::number(payload.size()) + " expected " +
          QString::number(_expected_bulk_size));
    }

    _user_messages[user_idx] = payload;

    // If this is my message, start timeout for other messages
    if(user_idx == static_cast<int>(_user_idx)) {
      // Set timeout clock running on finish, clock calls SendServerClientList()
      Utils::TimerCallback *timer_cb = new Dissent::Utils::TimerMethod<TolerantTreeRound, int>(this, 
          &TolerantTreeRound::SendServerClientList, 1);
      _timer_user_cutoff = Dissent::Utils::Timer::GetInstance().QueueCallback(timer_cb, GetUserCutoffInterval());
    }

    if(HasAllUserDataMessages()) {
      SendServerClientList(0);
    }
  }

  bool TolerantTreeRound::HasAllUserDataMessages() 
  {
    return (_user_messages.count() == _my_users.count());
  }

  void TolerantTreeRound::SendServerClientList(const int& code)
  {
    if(code) {
      qDebug() << "Callback triggered!";
    }

    // Clear timer
    _timer_user_cutoff.Stop();

    if(!_is_server) {
      qFatal("Non-server cannot send server client list");
    }

    // Stop accepting new messages 
    ChangeState(State_ServerClientListSharing);

    qDebug() << "My clients:" << _user_messages.keys();

    // Commit to next data packet
    QByteArray packet;
    QDataStream stream(&packet, QIODevice::WriteOnly);
    stream << MessageType_ServerClientListData << GetRoundId() << _phase << _user_messages.keys();

    VerifiableSendToServers(packet);
  }

  void TolerantTreeRound::HandleServerClientListData(QDataStream &stream, const Id &from)
  {
    qDebug() << _user_idx << GetLocalId().ToString() <<
      ": received server client list data from " << GetGroup().GetSubgroup().GetIndex(from) << from.ToString();

    if(_state != State_ServerClientListSharing) {
      throw QRunTimeError("Received a misordered ServerClientListData message");
    }

    if(!GetGroup().GetSubgroup().Contains(from)) {
      throw QRunTimeError("Receiving ServerClientListData message from a non-server");
    }

    uint idx = GetGroup().GetSubgroup().GetIndex(from);
    if(!_server_client_lists[idx].isEmpty()) {
      throw QRunTimeError("Already have server client list data.");
    }

    QList<uint> client_list;
    stream >> client_list;
    
    for(int user_idx=0; user_idx<client_list.count(); user_idx++) {
      Id client_id = GetGroup().GetId(client_list[user_idx]);
      if(!GetGroup().Contains(client_id)) {
        throw QRunTimeError("Client list contains invalid user index " 
            + QString::number(client_list[user_idx]));
      }
    }

    qDebug() << "Client list" << client_list;

    _server_client_lists[idx] = client_list;
    _received_server_client_lists++;

    if(HasAllServerClientLists()) {
      //qDebug() << _my_idx << "Sending server messages";
      ChangeState(State_ServerCommitSharing);
      SendServerCommit();
    }
  }

  bool TolerantTreeRound::HasAllServerClientLists()
  {
    return (_received_server_client_lists == static_cast<uint>(GetGroup().GetSubgroup().Count()));
  }

  void TolerantTreeRound::SendServerCommit()
  {
    if(!_is_server) {
      qFatal("Non-server cannot send server commits");
    }

    _active_clients_set.clear();
    for(int idx=0; idx<GetGroup().GetSubgroup().Count(); idx++) {
      _active_clients_set += _server_client_lists[idx].toSet();
    }

    qDebug() << "XORING for clients" << _active_clients_set;

    // Get the next data packet
    QByteArray server_xor_msg = GenerateServerXorMessage(_active_clients_set);
    QDataStream server_data_stream(&_server_next_packet, QIODevice::WriteOnly);
    server_data_stream << MessageType_ServerBulkData << GetRoundId() << _phase << server_xor_msg;

    // Commit to next data packet
    QByteArray server_commit_packet;
    QByteArray server_digest = _hash_algo->ComputeHash(_server_next_packet);
    QDataStream server_commit_stream(&server_commit_packet, QIODevice::WriteOnly);
    server_commit_stream << MessageType_ServerCommitData << GetRoundId() << _phase << server_digest;

    ChangeState(State_ServerCommitSharing);
    VerifiableSendToServers(server_commit_packet);
  }

  QByteArray TolerantTreeRound::GenerateServerXorMessage(const QSet<uint>& active_clients)
  {
    QByteArray msg;
    uint size = static_cast<uint>(_slot_signing_keys.size());

    // For each slot 
    for(uint slot_idx = 0; slot_idx < size; slot_idx++) {
      const uint length = _message_lengths[slot_idx] + _header_lengths[slot_idx];
      
      QByteArray slot_msg(length, 0);
      // For each user, XOR that users pad with the empty message
      for(int user_idx = 0; user_idx < GetGroup().Count(); user_idx++) {

        // Always generate string so that RNG is up to date
        QByteArray user_pad = GeneratePadWithUser(user_idx, length);

        if(active_clients.contains(user_idx)) {
          Xor(slot_msg, slot_msg, user_pad);
        }
      }
      
      msg.append(slot_msg);
      //qDebug() << "XOR length" << msg.count();
    }

    // XOR messages received from my users
    for(QHash<uint, QByteArray>::const_iterator i=_user_messages.begin();
        i!=_user_messages.end(); i++) {
      Xor(msg, msg, _user_messages[i.key()]);
    }

    return msg;
  }

  void TolerantTreeRound::HandleServerCommitData(QDataStream &stream, const Id &from)
  {
    qDebug() << _user_idx << GetLocalId().ToString() <<
      ": received server commit data from " << GetGroup().GetSubgroup().GetIndex(from) << from.ToString();

    if(_state != State_ServerCommitSharing) {
      throw QRunTimeError("Received a misordered ServerCommitData message");
    }

    if(!GetGroup().GetSubgroup().Contains(from)) {
      throw QRunTimeError("Receiving ServerCommitData message from a non-server");
    }

    uint idx = GetGroup().GetSubgroup().GetIndex(from);
    if(!_server_commits[idx].isEmpty()) {
      throw QRunTimeError("Already have server bulk commit data.");
    }

    QByteArray payload;
    stream >> payload;

    const int hash_len = _hash_algo->GetDigestSize();

    if(payload.size() != hash_len) {
      throw QRunTimeError("Incorrect server bulk commit message length, got " +
          QString::number(payload.size()) + " expected " +
          QString::number(hash_len));
    }

    _server_commits[idx] = payload;
    _received_server_commits++;

    if(HasAllServerCommits()) {
      //qDebug() << _my_idx << "Sending server messages";
      ChangeState(State_ServerDataSharing);
      VerifiableSendToServers(_server_next_packet);
    }
  }

  bool TolerantTreeRound::HasAllServerCommits()
  {
    return (_received_server_commits == static_cast<uint>(GetGroup().GetSubgroup().Count()));
  }

  void TolerantTreeRound::HandleServerBulkData(const QByteArray &packet, QDataStream &stream, const Id &from)
  {
    qDebug() << _user_idx << GetLocalId().ToString() <<
      ": received bulk server data from " << GetGroup().GetSubgroup().GetIndex(from) << from.ToString();

    if(_state != State_ServerDataSharing) {
      throw QRunTimeError("Received a misordered ServerBulkData message");
    }

    if(!_is_server) {
      throw QRunTimeError("Non-server received a ServerBulkData message");
    }

    if(!GetGroup().GetSubgroup().Contains(from)) {
      throw QRunTimeError("Got ServerBulkData message from a non-server");
    }

    uint idx = GetGroup().GetSubgroup().GetIndex(from);
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
    _server_message_digests[idx] = _hash_algo->ComputeHash(packet);

    qDebug() << "Received server" << _received_server_messages; 

    _received_server_messages++;
    if(HasAllServerDataMessages()) {
      SendServerFinalSig();
    }
  }

  bool TolerantTreeRound::HasAllServerDataMessages() 
  {
    return (_received_server_messages == static_cast<uint>(GetGroup().GetSubgroup().Count()));
  }


  void TolerantTreeRound::SendServerFinalSig()
  {
    if(!_is_server) {
      qFatal("Non-server cannot send server commits");
    }

    QVector<int> bad;
    CheckCommits(_server_commits, _server_message_digests, bad);
    if(bad.count()) {
      qDebug() << "Bad servers" << bad;
      qFatal("Server sent bad commit");
    }

    _final_data.clear();
    _final_data = QByteArray(_expected_bulk_size, 0);

    for(int idx=0; idx<_server_messages.count(); idx++) {
      Xor(_final_data, _final_data, _server_messages[idx]);
    }

    QByteArray server_sig = GetPrivateIdentity().GetSigningKey()->Sign(_final_data);

    // Send server packet
    QByteArray server_final_sig_packet;
    QDataStream stream(&server_final_sig_packet, QIODevice::WriteOnly);
    stream << MessageType_ServerFinalSig << GetRoundId() << _phase << server_sig;

    ChangeState(State_ServerFinalSigSharing);
    VerifiableSendToServers(server_final_sig_packet);
  }

  void TolerantTreeRound::HandleServerFinalSigData(QDataStream &stream, const Id &from)
  {
    qDebug() << _user_idx << GetLocalId().ToString() <<
      ": received server final sig data from " << GetGroup().GetSubgroup().GetIndex(from) << from.ToString();

    if(_state != State_ServerFinalSigSharing) {
      throw QRunTimeError("Received a misordered ServerCommitData message");
    }

    if(!GetGroup().GetSubgroup().Contains(from)) {
      throw QRunTimeError("Receiving ServerCommitData message from a non-server");
    }

    uint idx = GetGroup().GetSubgroup().GetIndex(from);
    if(!_server_final_sigs[idx].isEmpty()) {
      throw QRunTimeError("Already have server final sig data.");
    }

    QByteArray payload;
    stream >> payload;

    _server_final_sigs[idx] = payload;
    _received_server_final_sigs++;

    if(HasAllServerFinalSigMessages()) {
      ChangeState(State_UserFinalDataReceiving);
      BroadcastFinalMessages();
    }
  }

  bool TolerantTreeRound::HasAllServerFinalSigMessages()
  {
    return (_received_server_final_sigs == static_cast<uint>(GetGroup().GetSubgroup().Count()));
  }

  void TolerantTreeRound::BroadcastFinalMessages() 
  {
    QByteArray final_data_packet;
    QDataStream final_data_stream(&final_data_packet, QIODevice::WriteOnly);
    final_data_stream << MessageType_ServerFinalData << GetRoundId() << _phase 
      << _final_data << _server_final_sigs;

    ChangeState(State_UserFinalDataReceiving);
    VerifiableSendToUsers(final_data_packet);
  }

  void TolerantTreeRound::HandleServerFinalData(QDataStream &stream, const Id &from)
  {
    qDebug() << _user_idx << GetLocalId().ToString() <<
      ": received final bulk data from " << GetGroup().GetIndex(from) << from.ToString();

    if(_state != State_UserFinalDataReceiving) {
      throw QRunTimeError("Received a misordered FinalData message");
    }

    if(from != GetMyServerId()) {
      throw QRunTimeError("Received a LeaderBulkData message from a non-server");
    }

    QVector<QByteArray> server_sigs;
    QByteArray final_data;
    stream >> final_data >> server_sigs;
    
    if(server_sigs.count() != GetGroup().GetSubgroup().Count()) {
      throw QRunTimeError("Incorrect server sig vector length, got " +
          QString::number(server_sigs.count()) + " expected " +
          QString::number(GetGroup().GetSubgroup().Count()));
    }

    if(static_cast<uint>(final_data.size()) != _expected_bulk_size) {
      throw QRunTimeError("Incorrect leader bulk message length, got " +
          QString::number(final_data.size()) + " expected " +
          QString::number(_expected_bulk_size));
    }

    for(int server_idx=0; server_idx<GetGroup().GetSubgroup().Count(); server_idx++) {
      QSharedPointer<AsymmetricKey> verif_key = GetGroup().GetSubgroup().GetIdentity(server_idx).GetVerificationKey();
      if(!verif_key->Verify(final_data, server_sigs[server_idx])) {
        throw QRunTimeError("Signature on final data did not verify. Aborting.");
      }
    }

    // Split up messages into various slots
    ProcessMessages(final_data);

    if(_state == State_Finished) {
      return;   
    }

    if(_stop_next) {
      SetInterrupted();
      Stop("Peer joined"); 
      return;
    }

    qDebug() << "In" << ToString() << "ending phase.";
    PrepForNextPhase();
    _phase++;
    SendUserBulkData();
  }

  void TolerantTreeRound::ProcessMessages(const QByteArray &input)
  {
    const uint size = GetGroup().Count();

    uint msg_idx = 0;
    for(uint slot_idx = 0; slot_idx < size; slot_idx++) {
      int length = _message_lengths[slot_idx] + _header_lengths[slot_idx];
      QByteArray tcleartext = input.mid(msg_idx, length);
      QByteArray msg = ProcessMessage(tcleartext, slot_idx);
      if(!msg.isEmpty()) {
        qDebug() << ToString() << "received a valid message.";
        PushData(GetSharedPointer(), msg);
      }
      msg_idx += length;
    }
  }

  void TolerantTreeRound::CheckCommits(const QVector<QByteArray> &commits, const QVector<QByteArray> &digests,
      QVector<int> &bad)
  {
    if(commits.count() != digests.count()) {
      qFatal("Commits and messages vectors must have same length");
    }

    bad.clear();
    const int len = commits.count();
    for(int idx=0; idx<len; idx++) {
      if(commits[idx] != digests[idx]) {
        bad.append(idx);
      }
    }
  }

  QByteArray TolerantTreeRound::ProcessMessage(const QByteArray &slot_string, uint member_idx)
  {
    QSharedPointer<AsymmetricKey> verification_key(_slot_signing_keys[member_idx]);
    uint vkey_size = verification_key->GetKeySize() / 8;

    // Remove message randomization
    QByteArray cleartext = _message_randomizer.Derandomize(slot_string);

    QByteArray base = cleartext.mid(0, cleartext.size() - vkey_size - 1);
    QByteArray sig = cleartext.mid(cleartext.size() - vkey_size - 1, vkey_size);
   
    /*
    // Shuffle byte is the last byte in the randomized string
    char shuffle_byte = cleartext[cleartext.size()-1];
    bool is_my_message = _anon_signing_key->VerifyKey(*verification_key);
    */

    //qDebug() << "Slot" << slot_string.count() << "Clear" << cleartext.count() << "base" << base.count();

    // Verify the signature before doing anything
    if(verification_key->Verify(base, sig)) {
      uint found_phase = Serialization::ReadInt(cleartext, 0);
      if(found_phase != _phase) {
        qWarning() << "Received a message for an invalid phase:" << found_phase;
        return QByteArray();
      }

      _message_lengths[member_idx] = Serialization::ReadInt(cleartext, 4);

      qDebug() << "Found a message ... PUSHING! len=" << base.mid(8).count();
      return base.mid(8);
    } 

    // What to do if sig doesn't verify
    qWarning() << "Verification failed for message of length" << (base.size()-8) << ", slot: " << member_idx
      << "Message was either tampered with or user is offline";

    // Round should still go ahead even if verification
    // fails b/c of blame process
    return QByteArray();
  }

  QByteArray TolerantTreeRound::SignMessage(const QByteArray &message)
  {
    return _anon_signing_key->Sign(message);
  }

  QByteArray TolerantTreeRound::GenerateMyCleartextMessage()
  {

    QPair<QByteArray, bool> pair = GetData(1 << 16);

    const QByteArray cur_msg = _next_msg;
    _next_msg = pair.first;
    //qDebug() << "GetData(4096) =" << _next_msg;

    QByteArray cleartext(8, 0);
    Serialization::WriteInt(_phase, cleartext, 0);
    Serialization::WriteInt(_next_msg.size(), cleartext, 4);
    cleartext.append(cur_msg);

    QByteArray sig = SignMessage(cleartext);
    
    cleartext.append(sig);

    /* The shuffle byte */
    cleartext.append('\0');

    _last_msg_cleartext = cleartext;
    
    QByteArray randomized = _message_randomizer.Randomize(cleartext);
    _last_msg = randomized;

    qDebug() << "RANDOMIZED:" << randomized.count();
    return randomized;
  }

  QByteArray TolerantTreeRound::GeneratePadWithServer(uint server_idx, uint length)
  {
    QByteArray server_pad(length, 0);
    //qDebug() << "User bytes generated with server" << server_idx << "-- user" << _user_idx << "=" << _rngs_with_servers[server_idx]->BytesGenerated();
    _rngs_with_servers[server_idx]->GenerateBlock(server_pad);
    return server_pad;
  }

  QByteArray TolerantTreeRound::GeneratePadWithUser(uint user_idx, uint length)
  {
    QByteArray user_pad(length, 0);
    //qDebug() << "Server bytes generated with user" << user_idx << "-- server" << _server_idx << "=" << _rngs_with_users[user_idx]->BytesGenerated();
    _rngs_with_users[user_idx]->GenerateBlock(user_pad);
    return user_pad;
  }

  QByteArray TolerantTreeRound::GenerateUserXorMessage()
  {
    QByteArray msg;
    uint size = static_cast<uint>(_slot_signing_keys.size());

    /* For each slot */
    for(uint idx = 0; idx < size; idx++) {
      uint length = _message_lengths[idx] + _header_lengths[idx];
      QByteArray slot_msg(length, 0);
      //qDebug() << "=> STORE BYTES Phase" << _phase << " Slot" << idx << "Bytes=" << _rngs_with_servers[0]->BytesGenerated();

      /* For each server, XOR that server's pad with the empty message */
      for(int server_idx = 0; server_idx < _rngs_with_servers.count(); server_idx++) {
        QByteArray server_pad = GeneratePadWithServer(server_idx, length);
        Xor(slot_msg, slot_msg, server_pad);
      }
      qDebug() << "slot" << idx;

      /* This is my slot */
      if(idx == _my_idx) {
        QByteArray my_msg = GenerateMyCleartextMessage();
        Xor(slot_msg, slot_msg, my_msg);
      }

      msg.append(slot_msg);
      //qDebug() << "XOR length" << msg.count();
    }

    return msg;
  }


  void TolerantTreeRound::PrepForNextPhase()
  {
    uint group_size = static_cast<uint>(GetGroup().Count());

    _server_commits.clear();
    _server_commits.resize(GetGroup().GetSubgroup().Count());
    _received_server_commits = 0;

    _user_messages.clear();

    _server_messages.clear();
    _server_messages.resize(GetGroup().GetSubgroup().Count());

    _server_client_lists.clear();
    _server_client_lists.resize(GetGroup().GetSubgroup().Count());
    _received_server_client_lists = 0;

    _server_message_digests.clear();
    _server_message_digests.resize(GetGroup().GetSubgroup().Count());
    _received_server_messages = 0;

    _server_final_sigs.clear();
    _server_final_sigs.resize(GetGroup().GetSubgroup().Count());
    _received_server_final_sigs = 0;

    _expected_bulk_size = 0;
    for(uint idx = 0; idx < group_size; idx++) {
      _expected_bulk_size += _header_lengths[idx] + _message_lengths[idx];
    }

    _server_next_packet.clear();
  }

  void TolerantTreeRound::AddBadMember(int member_idx) {
    if(!_bad_members.contains(member_idx)) {
      _bad_members.append(member_idx);
    }
  }

  void TolerantTreeRound::AddBadMembers(const QVector<int> &more) {
    for(int i=0; i<more.count(); i++) {
      const int member_idx = more[i];
      AddBadMember(member_idx);
    }
  }

  void TolerantTreeRound::KeyShuffleFinished()
  {
    if(!_key_shuffle_round->Successful()) {
      AddBadMembers(_key_shuffle_round->GetBadMembers());
      FoundBadMembers();
      return;
    }

    if(_key_shuffle_sink.Count() != GetGroup().Count()) {
      qWarning() << "Did not receive a descriptor from everyone.";
    }

    uint count = static_cast<uint>(_key_shuffle_sink.Count());
    qDebug() << "Finished key shuffle" << count << "keys";
    for(uint idx = 0; idx < count; idx++) {
      QPair<QSharedPointer<ISender>, QByteArray> pair(_key_shuffle_sink.At(idx));
      _slot_signing_keys.append(ParseSigningKey(pair.second));
      
      // Header fields in every slot
      _header_lengths.append(1  // shuffle byte
          + 4                   // phase
          + 4                   // message length
          + (_slot_signing_keys.last()->GetKeySize() / 8) // signature
          + _message_randomizer.GetHeaderLength() // randomizer seed
        );

      // Everyone starts out with a zero-length message
      _message_lengths.append(0);

      qDebug() << "MSGLEN" << idx << "=" << _message_lengths[idx] << ", HEADER =" << _header_lengths[idx];
      if(_key_shuffle_data == pair.second) {
        _my_idx = idx;
      }
    }

    PrepForNextPhase();

    SendUserBulkData();
  }

  void TolerantTreeRound::ChangeState(State new_state) 
  {
    // Make a temp copy of the log
    Log log(_offline_log.Serialize());
    _offline_log.Clear();

    _state = new_state;

    uint count = static_cast<uint>(log.Count());
    for(uint idx = 0; idx < count; idx++) {
      QPair<QByteArray, Id> entry = log.At(idx);
      ProcessData(entry.second, entry.first);
    }

    qDebug() << "Done changing state";
  }

  bool TolerantTreeRound::ReadyForMessage(MessageType mtype)
  {
    switch(_state) {
      case State_Offline: 
        return false;
      case State_SigningKeyShuffling:
        return false;
      case State_ServerUserDataReceiving:
        return (mtype == MessageType_UserBulkData);
      case State_ServerClientListSharing:  
        return (mtype == MessageType_ServerClientListData);
      case State_ServerCommitSharing:  
        return (mtype == MessageType_ServerCommitData);
      case State_ServerDataSharing:
        return (mtype == MessageType_ServerBulkData);
      case State_ServerFinalSigSharing:
        return (mtype == MessageType_ServerFinalSig);
      case State_UserFinalDataReceiving:
        return (mtype == MessageType_ServerFinalData);
      case State_Finished:
        qWarning() << "Received message after node finished";
        return false;
      default:
        qFatal("Should never get here");

      return false;
    }
  }

  void TolerantTreeRound::VerifiableSendToUsers(const QByteArray &msg) 
  {
    for(int idx=0; idx<_my_users.count(); idx++) {
      qDebug() << GetGroup().GetIndex(GetLocalId()) << "Sending msg len" << msg.count() << "to user" << idx;
      VerifiableSend(_my_users[idx], msg);
    }
  }

  void TolerantTreeRound::VerifiableSendToServers(const QByteArray &msg) { 
    for(int idx=0; idx<GetGroup().GetSubgroup().Count(); idx++) {
      qDebug() << GetGroup().GetIndex(GetLocalId()) << "Sending msg len" << msg.count() << "to server" << idx;
      VerifiableSend(GetGroup().GetSubgroup().GetId(idx), msg); 
    }
  }

}
}
}
