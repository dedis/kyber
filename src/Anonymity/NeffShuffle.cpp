#include <QThreadPool>
#include "Crypto/CppDsaPrivateKey.hpp"
#include "Crypto/CppDsaPublicKey.hpp"
#include "Crypto/CppNeffShuffle.hpp"
#include "Identity/PublicIdentity.hpp"
#include "Utils/QRunTimeError.hpp"
#include "Utils/Timer.hpp"
#include "Utils/TimerCallback.hpp"

#include "NeffShuffle.hpp"

namespace Dissent {
  using Crypto::CppDsaPrivateKey;
  using Crypto::CppDsaPublicKey;
  using Crypto::CppNeffShuffle;
  using Identity::PublicIdentity;
  using Utils::QRunTimeError;

namespace Anonymity {
  NeffShuffle::NeffShuffle(const Group &group,
      const PrivateIdentity &ident, const Id &round_id,
      QSharedPointer<Network> network,
      GetDataCallback &get_data,
      bool key_shuffle) :
    Round(group, ident, round_id, network, get_data),
    _state_machine(this)
  {
    _state_machine.AddState(OFFLINE);
    _state_machine.AddState(MSG_GENERATION, -1, 0, &NeffShuffle::GenerateMessage);
    _state_machine.AddState(MSG_SUBMISSION, -1, 0, &NeffShuffle::SubmitMessage);
    _state_machine.AddState(FINISHED);
    _state_machine.SetState(OFFLINE);

    if(group.GetSubgroup().Contains(ident.GetLocalId())) {
      InitServer();
    } else {
      InitClient();
    }
    _state->key_shuffle = key_shuffle;
  }

  NeffShuffle::~NeffShuffle()
  {
  }

  void NeffShuffle::VerifiableBroadcastToServers(const QByteArray &data)
  { 
    Q_ASSERT(IsServer());
    
    QByteArray msg = data + GetSigningKey()->Sign(data);
    foreach(const PublicIdentity &pi, GetGroup().GetSubgroup()) {
      GetNetwork()->Send(pi.GetId(), msg);
    }
  }
    
  void NeffShuffle::VerifiableBroadcastToClients(const QByteArray &data)
  {
    Q_ASSERT(IsServer());
  
    QByteArray msg = data + GetSigningKey()->Sign(data);
    foreach(const QSharedPointer<Connection> &con,
        GetNetwork()->GetConnectionManager()->
        GetConnectionTable().GetConnections())
    {
      if(!GetGroup().Contains(con->GetRemoteId()) ||
          GetGroup().GetSubgroup().Contains(con->GetRemoteId()))
      { 
        continue;
      }
          
      GetNetwork()->Send(con->GetRemoteId(), msg);
    }   
  }   

  void NeffShuffle::InitServer()
  {
    _server_state = QSharedPointer<ServerState>(new ServerState());
    _state = _server_state;

    _state_machine.AddState(KEY_GENERATION, -1, 0, &NeffShuffle::GenerateKey);
    _state_machine.AddState(KEY_EXCHANGE, -1, 0, &NeffShuffle::SubmitKey);
    _state_machine.AddState(WAITING_FOR_KEYS, MSG_KEY_EXCH, &NeffShuffle::HandleKey);
    _state_machine.AddState(SUBMIT_KEY_SIGNATURE, -1, 0,
        &NeffShuffle::SubmitKeySignature);
    _state_machine.AddState(WAITING_FOR_KEY_SIGNATURES, MSG_KEY_SIGNATURE,
        &NeffShuffle::HandleKeySignature);
    _state_machine.AddState(PUSH_SERVER_KEYS, -1, 0, &NeffShuffle::PushServerKeys);

    if(GetGroup().GetSubgroup().GetIndex(GetLocalId()) == 0) {
      _state_machine.AddState(WAITING_FOR_MSGS, MSG_SUBMIT,
          &NeffShuffle::HandleMessageSubmission,
          &NeffShuffle::PrepareForMessageSubmissions);
    } else {
      _state_machine.AddState(WAITING_FOR_SHUFFLES_BEFORE_TURN, MSG_SHUFFLE,
          &NeffShuffle::HandleShuffle);
    }

    _state_machine.AddState(SHUFFLING, -1, 0, &NeffShuffle::ShuffleMessages);
    _state_machine.AddState(TRANSMIT_SHUFFLE, -1, 0, &NeffShuffle::TransmitShuffle);
    _state_machine.AddState(WAITING_FOR_SHUFFLES_AFTER_TURN, MSG_SHUFFLE,
        &NeffShuffle::HandleShuffle);

    _state_machine.AddState(SUBMIT_SIGNATURE, -1, 0, &NeffShuffle::SubmitSignature);
    _state_machine.AddState(WAITING_FOR_SIGNATURES,
        MSG_SIGNATURE, &NeffShuffle::HandleSignature);
    _state_machine.AddState(PUSH_OUTPUT, -1, 0, &NeffShuffle::PushMessages);

    _state_machine.AddTransition(OFFLINE, KEY_GENERATION);
    _state_machine.AddTransition(KEY_GENERATION, KEY_EXCHANGE);
    _state_machine.AddTransition(KEY_EXCHANGE, WAITING_FOR_KEYS);
    _state_machine.AddTransition(WAITING_FOR_KEYS, SUBMIT_KEY_SIGNATURE);
    _state_machine.AddTransition(SUBMIT_KEY_SIGNATURE, WAITING_FOR_KEY_SIGNATURES);
    _state_machine.AddTransition(WAITING_FOR_KEY_SIGNATURES, PUSH_SERVER_KEYS);
    _state_machine.AddTransition(PUSH_SERVER_KEYS, MSG_GENERATION);
    _state_machine.AddTransition(MSG_GENERATION, MSG_SUBMISSION);

    if(GetGroup().GetSubgroup().GetIndex(GetLocalId()) == 0) {
      _state_machine.AddTransition(MSG_SUBMISSION, WAITING_FOR_MSGS);
      _state_machine.AddTransition(WAITING_FOR_MSGS, SHUFFLING);
    } else {
      _state_machine.AddTransition(MSG_SUBMISSION, WAITING_FOR_SHUFFLES_BEFORE_TURN);
      _state_machine.AddTransition(WAITING_FOR_SHUFFLES_BEFORE_TURN, SHUFFLING);
    }

    _state_machine.AddTransition(SHUFFLING, TRANSMIT_SHUFFLE);
    _state_machine.AddTransition(TRANSMIT_SHUFFLE, WAITING_FOR_SHUFFLES_AFTER_TURN);
    _state_machine.AddTransition(WAITING_FOR_SHUFFLES_AFTER_TURN, SUBMIT_SIGNATURE);
    _state_machine.AddTransition(SUBMIT_SIGNATURE, WAITING_FOR_SIGNATURES);
    _state_machine.AddTransition(WAITING_FOR_SIGNATURES, PUSH_OUTPUT);
  }

  void NeffShuffle::InitClient()
  {
    _state = QSharedPointer<State>(new State());

    _state_machine.AddState(WAITING_FOR_SERVER_KEYS, MSG_KEY_DIST, &NeffShuffle::HandleServerKeys);
    _state_machine.AddState(WAITING_FOR_OUTPUT, MSG_OUTPUT,
        &NeffShuffle::HandleOutput);

    _state_machine.AddTransition(OFFLINE, WAITING_FOR_SERVER_KEYS);
    _state_machine.AddTransition(WAITING_FOR_SERVER_KEYS, MSG_GENERATION);
    _state_machine.AddTransition(MSG_GENERATION, MSG_SUBMISSION);
    _state_machine.AddTransition(MSG_SUBMISSION, WAITING_FOR_OUTPUT);
  }

  void NeffShuffle::OnStart()
  {
    Round::OnStart();
    _state_machine.StateComplete();
  }

  void NeffShuffle::OnStop()
  {
    Round::OnStop();
  }

  void NeffShuffle::HandleDisconnect(const Id &id)
  {
    if(!GetGroup().Contains(id)) {
      return;
    }

    if(GetGroup().GetSubgroup().Contains(id)) {
      qDebug() << "A server (" << id << ") disconnected.";
      SetInterrupted();
      Stop("A server (" + id.ToString() +") disconnected.");
    } else {
      qDebug() << "A client (" << id << ") disconnected, ignoring.";
    }
  }

  void NeffShuffle::HandleKey(const Id &from,
      QDataStream &stream)
  {
    int gidx = GetGroup().GetSubgroup().GetIndex(from);
    if(_server_state->server_keys[gidx]) {
      throw QRunTimeError("Received multiples keys.");
    }

    QSharedPointer<AsymmetricKey> key;
    stream >> key;
    if(!key || !key->IsValid()) {
      throw QRunTimeError("Invalid key");
    }

    QSharedPointer<PublicKeyType> tkey = key.dynamicCast<PublicKeyType>();
    if(!tkey) {
      throw QRunTimeError("Invalid key type");
    }

    if(!_server_state->my_key->InGroup(tkey->GetPublicElement())) {
      throw QRunTimeError("Invalid generator used.");
    }

    /// @todo check proof of ownership

    _server_state->server_keys[gidx] = key;
    _server_state->msgs_received++;

    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId() <<
        ": received key from" << GetGroup().GetIndex(from) << from <<
        "Have:" << _server_state->msgs_received << "expect:" <<
        GetGroup().GetSubgroup().Count();

    if(_server_state->msgs_received == GetGroup().GetSubgroup().Count()) {
      _state_machine.StateComplete();
    }
  }

  void NeffShuffle::HandleKeySignature(const Id &from,
      QDataStream &stream)
  {
    int gidx = GetGroup().GetSubgroup().GetIndex(from);
    if(!_server_state->key_signatures[gidx].isEmpty()) {
      throw QRunTimeError("Received multiples key signatures.");
    }

    QByteArray signature;
    stream >> signature;

    if(!GetGroup().GetIdentity(from).GetVerificationKey()->Verify(
          _server_state->key_hash, signature))
    {
      throw QRunTimeError("Invalid key signature");
    }

    _server_state->key_signatures[gidx] = signature;
    _server_state->msgs_received++;

    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId() <<
        ": received key signature from" << GetGroup().GetIndex(from) << from <<
        "Have:" << _server_state->msgs_received << "expect:" <<
        GetGroup().GetSubgroup().Count();

    if(_server_state->msgs_received == GetGroup().GetSubgroup().Count()) {
      _state_machine.StateComplete();
    }
  }

  void NeffShuffle::HandleServerKeys(const Id &from,
      QDataStream &stream)
  {
    if(!GetGroup().GetSubgroup().Contains(from)) {
      throw QRunTimeError("Received from a non-server");
    }

    QVector<QSharedPointer<AsymmetricKey> > server_keys;
    QVector<QByteArray> server_signatures;
    stream >> server_keys >> server_signatures;

    if(GetGroup().GetSubgroup().Count() != server_keys.size()) {
      throw QRunTimeError("Missing some server keys");
    } else if(GetGroup().GetSubgroup().Count() != server_signatures.size()) {
      throw QRunTimeError("Missing some server signatures");
    }

    QSharedPointer<Crypto::Hash> hash(Crypto::CryptoFactory::GetInstance().
        GetLibrary()->GetHashAlgorithm());

    foreach(const QSharedPointer<AsymmetricKey> &key, server_keys) {
      hash->Update(key->GetByteArray());
    }
    QByteArray key_hash = hash->ComputeHash();

    for(int idx = 0; idx < GetGroup().GetSubgroup().Count(); idx++) {
      Id id = GetGroup().GetSubgroup().GetId(idx);
      QSharedPointer<AsymmetricKey> key(GetGroup().GetKey(id));
      if(!key->Verify(key_hash, server_signatures[idx])) {
        throw QRunTimeError("Invalid signature");
      }
    }

    _state->server_keys = server_keys;

    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId() <<
        ": received keys from" << GetGroup().GetIndex(from) << from;
    _state_machine.StateComplete();
  }

  // not really done but good enough
  void NeffShuffle::HandleMessageSubmission(const Id &from,
      QDataStream &stream)
  {
    int gidx = GetGroup().GetIndex(from);
    if(!_server_state->initial_input[gidx].isEmpty()) {
      throw QRunTimeError("Received multiples data messages.");
    }

    QByteArray msg;
    stream >> msg;

    if(!_server_state->my_key->InGroup(msg)) {
      throw QRunTimeError("Invalid element pair");
    }
    
    _server_state->initial_input[gidx] = msg;
    ++_server_state->msgs_received;
    
    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId() <<
        ": received msg from" << GetGroup().GetIndex(from) << from <<
        "Have:" << _server_state->msgs_received << "expect:" << GetGroup().Count();

    if(_server_state->msgs_received == GetGroup().Count()) {
      _server_state->msg_receive_period.Stop();
      _server_state->next_verify_input = _server_state->initial_input;
      _state_machine.StateComplete();
    }
  }

  void NeffShuffle::HandleShuffle(const Id &from, QDataStream &stream)
  {
    if(!GetGroup().GetSubgroup().Contains(from)) {
      throw QRunTimeError("Received from a non-server");
    } else if(_server_state->shuffle_proof.contains(from)) {
      throw QRunTimeError("Already received a proof from this member");
    }

    if(GetGroup().GetSubgroup().GetIndex(from) == 0) {
      stream >> _server_state->initial_input;
      _server_state->next_verify_input = _server_state->initial_input;
    }

    QByteArray transcript;
    stream >> transcript;

    _server_state->shuffle_proof[from] = transcript;

    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId() <<
        ": received shuffle data from" << GetGroup().GetIndex(from) << from;

    int index = GetGroup().GetSubgroup().GetIndex(from);
    if(index == _server_state->new_end_verify_idx) {
      int increment = 0;
      for(Id current = from; _server_state->shuffle_proof.contains(current);
          current = GetGroup().GetSubgroup().Next(current))
      {
        increment++;
      }

      if(_server_state->verifying) {
        _server_state->new_end_verify_idx += increment;
      } else {
        _server_state->new_end_verify_idx += increment;
        _server_state->end_verify_idx += increment;
        VerifyShuffles();
      }
    }
  }

  void NeffShuffle::HandleSignature(const Id &from, QDataStream &stream)
  {
    if(!GetGroup().GetSubgroup().Contains(from)) {
      throw QRunTimeError("Received from a non-server");
    } else if(_server_state->signatures.contains(from)) {
      throw QRunTimeError("Already received a proof from this member");
    }

    QByteArray signature;
    stream >> signature;

    if(!GetGroup().GetKey(from)->Verify(_server_state->cleartext_hash, signature)) {
      throw QRunTimeError("Invalid signature for cleartext");
    }

    _server_state->signatures[from] = signature;

    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId() <<
        ": received signature from" << GetGroup().GetIndex(from) << from <<
        "Have:" << _server_state->signatures.size() << "expect:" <<
        GetGroup().GetSubgroup().Count();

    if(_server_state->signatures.size() == GetGroup().GetSubgroup().Count()) {
      _state_machine.StateComplete();
    }
  }

  void NeffShuffle::HandleOutput(const Id &from, QDataStream &stream)
  {
    if(!GetGroup().GetSubgroup().Contains(from)) {
      throw QRunTimeError("Received from a non-server");
    }

    QVector<QByteArray> cleartext;
    QHash<Id, QByteArray> signatures;
    stream >> cleartext >> signatures;

    if(signatures.size() != GetGroup().GetSubgroup().Count()) {
      throw QRunTimeError("Missing signatures");
    }

    QSharedPointer<Crypto::Hash> hash(Crypto::CryptoFactory::GetInstance().
        GetLibrary()->GetHashAlgorithm());

    foreach(const QByteArray &msg, cleartext) {
      hash->Update(msg);
    }
    QByteArray cleartext_hash = hash->ComputeHash();

    for(int idx = 0; idx < signatures.size(); idx++) {
      Id id = GetGroup().GetSubgroup().GetId(idx);
      QSharedPointer<AsymmetricKey> key(GetGroup().GetKey(id));
      if(!key->Verify(cleartext_hash, signatures[id])) {
        throw QRunTimeError("Invalid signature");
      }
    }

    _state->cleartext = cleartext;

    foreach(const QByteArray &msg, _state->cleartext) {
      if(msg.isEmpty()) {
        continue;
      }
      PushData(GetSharedPointer(), msg);
    }

    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId() <<
        ": received cleartext from" << GetGroup().GetIndex(from) << from;
    SetSuccessful(true);
    Stop("Round finished");
  }

  void NeffShuffle::GenerateKey()
  {
    NeffShufflePrivate::KeyGeneration *keygen =
      new NeffShufflePrivate::KeyGeneration(this);
    QObject::connect(keygen, SIGNAL(Finished()),
        this, SLOT(OperationFinished()));
    QThreadPool::globalInstance()->start(keygen);
  }

  void NeffShuffle::SubmitKey()
  {
    _server_state->msgs_received = 0;
    QSharedPointer<AsymmetricKey> key(_server_state->my_key->GetPublicKey());

    QByteArray out;
    QDataStream stream(&out, QIODevice::WriteOnly);
    stream << MSG_KEY_EXCH << GetRoundId() << key;
    _server_state->server_keys.resize(GetGroup().GetSubgroup().Count());
    VerifiableBroadcastToServers(out);
    _state_machine.StateComplete();
  }

  void NeffShuffle::SubmitKeySignature()
  {
    QSharedPointer<Crypto::Hash> hash(Crypto::CryptoFactory::GetInstance().
        GetLibrary()->GetHashAlgorithm());

    foreach(const QSharedPointer<AsymmetricKey> &key, _server_state->server_keys) {
      hash->Update(key->GetByteArray());
    }
    _server_state->key_hash = hash->ComputeHash();

    QByteArray signature = GetPrivateIdentity().GetSigningKey()->Sign(_server_state->key_hash);

    QByteArray out;
    QDataStream stream(&out, QIODevice::WriteOnly);
    stream << MSG_KEY_SIGNATURE << GetRoundId() << signature;
    VerifiableBroadcastToServers(out);
    _server_state->key_signatures.resize(GetGroup().GetSubgroup().Count());
    _server_state->msgs_received = 0;
    _state_machine.StateComplete();
  }

  void NeffShuffle::PushServerKeys()
  {
    _server_state->next_verify_keys = _server_state->server_keys;
    QByteArray out;
    QDataStream stream(&out, QIODevice::WriteOnly);
    stream << MSG_KEY_DIST << GetRoundId() << _server_state->server_keys
      << _server_state->key_signatures;
    VerifiableBroadcastToClients(out);
    _state_machine.StateComplete();
  }

  void NeffShuffle::GenerateMessage()
  {
    QSharedPointer<CppDsaPublicKey> pkey =
      _state->server_keys[0].dynamicCast<CppDsaPublicKey>();
    if(!pkey) {
      qFatal("Unable to do NeffShuffle without Dsa server keys");
    }

    if(_state->key_shuffle) {
      QSharedPointer<CppDsaPrivateKey> key(
          new CppDsaPrivateKey(pkey->GetModulus(),
            pkey->GetSubgroup(), pkey->GetGenerator()));
      _state->private_key = key;

      _state->input = key->GetPublicElement().GetByteArray();
    } else {
      QPair<QByteArray, bool> input = GetData(pkey->GetKeySize() - 3);
      _state->input = input.first;
    }

    _state->input = CppDsaPublicKey::SeriesEncrypt(_state->server_keys, _state->input);
    _state_machine.StateComplete();
  }

  void NeffShuffle::SubmitMessage()
  {
    QByteArray msg;
    QDataStream stream(&msg, QIODevice::WriteOnly);

    stream << MSG_SUBMIT << GetRoundId() << _state->input;

    VerifiableSend(GetGroup().GetSubgroup().GetId(0), msg);
    _state_machine.StateComplete();
  }

  void NeffShuffle::PrepareForMessageSubmissions()
  {
    _server_state->initial_input = QVector<QByteArray>(GetGroup().Count(), 0);
    _server_state->msgs_received = 0;

    Utils::TimerCallback *cb = new Utils::TimerMethod<NeffShuffle, int>(
        this, &NeffShuffle::ConcludeMessageSubmission, 0);
    _server_state->msg_receive_period =
      Utils::Timer::GetInstance().QueueCallback(cb, MSG_SUBMISSION_WINDOW);
  }

  void NeffShuffle::ShuffleMessages()
  {
    NeffShufflePrivate::ShuffleMessages *shuffler =
      new NeffShufflePrivate::ShuffleMessages(this);
    QObject::connect(shuffler, SIGNAL(Finished()),
        this, SLOT(OperationFinished()));
    QThreadPool::globalInstance()->start(shuffler);
  }

  void NeffShuffle::TransmitShuffle()
  {
    QByteArray transcript = _server_state->shuffle_proof.value(GetLocalId());
    _server_state->shuffle_proof.remove(GetLocalId());

    QByteArray msg;
    QDataStream stream(&msg, QIODevice::WriteOnly);
    stream << MSG_SHUFFLE << GetRoundId();
    // Hack for now to transmit the first batch of messages
    if(GetGroup().GetSubgroup().GetIndex(GetLocalId()) == 0) {
      stream << _server_state->initial_input;
    }
    stream << transcript;
    VerifiableBroadcastToServers(msg);

    _state_machine.StateComplete();
  }

  void NeffShuffle::VerifyShuffles()
  {
    NeffShufflePrivate::VerifyShuffles *verifier =
      new NeffShufflePrivate::VerifyShuffles(this);
    QObject::connect(verifier, SIGNAL(Finished()),
        this, SLOT(VerifyShufflesDone()));
    QThreadPool::globalInstance()->start(verifier);
  }

  void NeffShuffle::VerifyShufflesDone()
  {
    _server_state->verifying = false;
    if(_server_state->new_end_verify_idx != _server_state->end_verify_idx) {
      _server_state->end_verify_idx = _server_state->new_end_verify_idx;
      VerifyShuffles();
      return;
    }

    if(_server_state->end_verify_idx == GetGroup().GetSubgroup().GetIndex(GetLocalId())) {
      _state_machine.StateComplete();
      return;
    }

    if(_server_state->end_verify_idx == GetGroup().GetSubgroup().Count()) {
      _state_machine.StateComplete();
    }
  }

  void NeffShuffle::SubmitSignature()
  {
    QSharedPointer<Crypto::Hash> hash(Crypto::CryptoFactory::GetInstance().
        GetLibrary()->GetHashAlgorithm());

    foreach(const QByteArray &message, _state->cleartext) {
      hash->Update(message);
    }

    _server_state->cleartext_hash = hash->ComputeHash();
    QByteArray signature = GetPrivateIdentity().
      GetSigningKey()->Sign(_server_state->cleartext_hash);

    QByteArray msg;
    QDataStream stream(&msg, QIODevice::WriteOnly);
    stream << MSG_SIGNATURE << GetRoundId() << signature;
    VerifiableBroadcastToServers(msg);
    _state_machine.StateComplete();
  }
  
  void NeffShuffle::PushMessages()
  {
    QByteArray msg;
    QDataStream stream(&msg, QIODevice::WriteOnly);
    stream << MSG_OUTPUT << GetRoundId() << _server_state->cleartext <<
      _server_state->signatures;
    VerifiableBroadcastToClients(msg);

    foreach(const QByteArray &msg, _server_state->cleartext) {
      if(msg.isEmpty()) {
        continue;
      }

      PushData(GetSharedPointer(), msg);
    }

    SetSuccessful(true);
    Stop("Round finished");
  }

  void NeffShuffle::ConcludeMessageSubmission(const int &)
  {
    qDebug() << "Msg window has closed, unfortunately some keys may not"
      << "have transmitted in time.";

    QVector<QByteArray> pruned;
    foreach(const QByteArray &input, _server_state->initial_input) {
      if(input.isEmpty()) {
        continue;
      }
      pruned.append(input);
    }

    _server_state->initial_input = pruned;

    _state_machine.StateComplete();
  }

  void NeffShuffle::OperationFinished()
  {
    _state_machine.StateComplete();
  }

namespace NeffShufflePrivate {
  void KeyGeneration::run()
  {
    QSharedPointer<CppDsaPrivateKey> base_key;
    if(_shuffle->_server_state->key_shuffle) {
      base_key = QSharedPointer<CppDsaPrivateKey>(
          CppDsaPrivateKey::GenerateKey(
            _shuffle->GetRoundId().GetByteArray(), 1024));
    } else {
      base_key = QSharedPointer<CppDsaPrivateKey>(
          CppDsaPrivateKey::GenerateKey(_shuffle->GetRoundId().GetByteArray(), 2048, 2047));
    }

    _shuffle->_server_state->my_key = QSharedPointer<CppDsaPrivateKey>(
        new CppDsaPrivateKey(base_key->GetModulus(), base_key->GetSubgroup(),
          base_key->GetGenerator()));

    emit Finished();
  }

  void ShuffleMessages::run()
  {
    QVector<QByteArray> input = _shuffle->_server_state->next_verify_input;
    QVector<QSharedPointer<Crypto::AsymmetricKey> > remaining_keys =
      _shuffle->_server_state->next_verify_keys;
    remaining_keys.pop_front();
    QVector<QByteArray> output;
    QByteArray transcript;

    CppNeffShuffle shuffle;
    shuffle.Shuffle(input, _shuffle->_server_state->my_key,
        remaining_keys, output, transcript);

//    _shuffle->_server_state->next_verify_input = input;//output;
//    _shuffle->_server_state->next_verify_idx = my_idx;// my_idx+1
//    _shuffle->_server_state->next_verify_keys = tkeys; //remaining_keys;
    _shuffle->_server_state->shuffle_proof[_shuffle->GetLocalId()] = transcript; // null

    emit Finished();
  }

  void VerifyShuffles::run()
  {
    QVector<QSharedPointer<Crypto::AsymmetricKey> > remaining_keys =
      _shuffle->_server_state->next_verify_keys;
    QVector<QByteArray> input = _shuffle->_server_state->next_verify_input;
    QVector<QByteArray> output;
    CppNeffShuffle shuffle;

    for(int idx = _shuffle->_server_state->next_verify_idx; 
        idx < _shuffle->_server_state->end_verify_idx; idx++)
    {
      Connections::Id id = _shuffle->GetGroup().GetSubgroup().GetId(idx);
      QByteArray transcript = _shuffle->_server_state->shuffle_proof[id];
      if(!shuffle.Verify(input, remaining_keys, transcript, output)) {
        qCritical() << "Invalid transcript from" << id << "at idx" << idx;
      }
      input = output;
      remaining_keys.pop_front();
    }

    _shuffle->_server_state->next_verify_keys = remaining_keys;
    _shuffle->_server_state->next_verify_input = input;
    _shuffle->_server_state->next_verify_idx = _shuffle->_server_state->end_verify_idx;

    if(_shuffle->_server_state->end_verify_idx == _shuffle->GetGroup().GetSubgroup().Count()) {
      _shuffle->_state->cleartext.clear();
      foreach(const QByteArray &pair, output) {
        _shuffle->_server_state->cleartext.append(
            _shuffle->_server_state->my_key->SeriesDecryptFinish(pair));
      }
    }

    emit Finished();
  }
}
}
}
