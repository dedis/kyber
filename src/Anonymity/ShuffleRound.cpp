#include <QRunnable>

#include "Crypto/CryptoFactory.hpp"
#include "Crypto/Hash.hpp"
#include "Utils/Serialization.hpp"
#include "Utils/QRunTimeError.hpp"

#include "ShuffleRound.hpp"
#include "ShuffleBlamer.hpp"


namespace Dissent {

using Crypto::CryptoFactory;
using Crypto::Hash;
using Crypto::Library;
using Crypto::OnionEncryptor;
using Utils::QRunTimeError;

namespace Anonymity {

using namespace ShuffleRoundPrivate;

  const QByteArray ShuffleRound::DefaultData = QByteArray(ShuffleRound::BlockSize + 4, 0);

  ShuffleRound::ShuffleRound(const Group &group,
      const PrivateIdentity &ident, const Id &round_id,
      QSharedPointer<Network> network, GetDataCallback &get_data) :
    Round(group, ident, round_id, network, get_data),
    _shufflers(GetGroup().GetSubgroup()),
    _state_machine(RoundStateMachine<ShuffleRound>(this))
  {
    RegisterMetaTypes();

    _state_machine.AddState(OFFLINE);
    _state_machine.AddState(FINISHED);

    _state_machine.AddState(WAITING_FOR_PUBLIC_KEYS, PUBLIC_KEYS,
        &ShuffleRound::HandlePublicKeys);

    _state_machine.AddState(CIPHERTEXT_GENERATION, -1, 0,
        &ShuffleRound::GenerateCiphertext);

    _state_machine.AddState(SUBMIT_CIPHERTEXT, -1, 0,
        &ShuffleRound::SubmitCiphertext);

    _state_machine.AddState(WAITING_FOR_ENCRYPTED_INNER_DATA, ENCRYPTED_DATA,
        &ShuffleRound::HandleDataBroadcast);

    _state_machine.AddState(VERIFICATION, -1, 0,
        &ShuffleRound::VerifyInnerCiphertext);

    _state_machine.AddState(WAITING_FOR_PRIVATE_KEYS, PRIVATE_KEY,
        &ShuffleRound::HandlePrivateKey,
        &ShuffleRound::PrepareForPrivateKeys);

    _state_machine.AddState(DECRYPTION, -1, 0,
        &ShuffleRound::Decrypt);

    _state_machine.AddState(BLAME_SHARE, BLAME_DATA,
        &ShuffleRound::HandleBlame,
        &ShuffleRound::StartBlame);

    _state_machine.AddState(BLAME_VERIFY, BLAME_VERIFICATION,
        &ShuffleRound::HandleBlameVerification,
        &ShuffleRound::BroadcastBlameVerification);

    _state_machine.AddState(BLAME_REVIEWING, -1, 0,
        &ShuffleRound::BlameRound);

    if(_shufflers.Contains(GetLocalId())) {
      InitServer();
    } else {
      InitClient();
    }

    _state_machine.AddTransition(WAITING_FOR_PRIVATE_KEYS, DECRYPTION);

    _state_machine.AddTransition(BLAME_SHARE, BLAME_VERIFY);
    _state_machine.AddTransition(BLAME_VERIFY, BLAME_REVIEWING);

    _state_machine.SetState(OFFLINE);
  }

  void ShuffleRound::InitServer()
  {
    bool first_server = GetGroup().GetSubgroup().GetIndex(GetLocalId()) == 0;
    _server_state = QSharedPointer<ServerState>(new ServerState());
    _state = _server_state;

    _state_machine.AddState(KEY_SHARING, -1, 0,
        &ShuffleRound::BroadcastPublicKeys);

    if(first_server) {
      _state_machine.AddState(WAITING_FOR_INITIAL_DATA, DATA,
          &ShuffleRound::HandleData, &ShuffleRound::PrepareForInitialData);
    } else {
      _state_machine.AddState(WAITING_FOR_SHUFFLE, SHUFFLE_DATA,
          &ShuffleRound::HandleShuffle);
    }

    _state_machine.AddState(SHUFFLING, -1, 0, &ShuffleRound::Shuffle);

    _state_machine.AddState(WAITING_FOR_VERIFICATION_MESSAGES, GO_MESSAGE,
        &ShuffleRound::HandleVerification, &ShuffleRound::PrepareForVerification);

    _state_machine.AddState(PRIVATE_KEY_SHARING, -1, 0,
        &ShuffleRound::BroadcastPrivateKey);

    _state_machine.AddTransition(OFFLINE, KEY_SHARING);
    _state_machine.AddTransition(KEY_SHARING, WAITING_FOR_PUBLIC_KEYS);
    _state_machine.AddTransition(WAITING_FOR_PUBLIC_KEYS,
        CIPHERTEXT_GENERATION);
    _state_machine.AddTransition(CIPHERTEXT_GENERATION, SUBMIT_CIPHERTEXT);

    if(first_server) {
      _state_machine.AddTransition(SUBMIT_CIPHERTEXT,
          WAITING_FOR_INITIAL_DATA);
      _state_machine.AddTransition(WAITING_FOR_INITIAL_DATA, SHUFFLING);
    } else {
      _state_machine.AddTransition(SUBMIT_CIPHERTEXT,
          WAITING_FOR_SHUFFLE);
      _state_machine.AddTransition(WAITING_FOR_SHUFFLE, SHUFFLING);
    }

    _state_machine.AddTransition(SHUFFLING,
        WAITING_FOR_ENCRYPTED_INNER_DATA);
    _state_machine.AddTransition(WAITING_FOR_ENCRYPTED_INNER_DATA,
        VERIFICATION);
    _state_machine.AddTransition(VERIFICATION,
        WAITING_FOR_VERIFICATION_MESSAGES);
    _state_machine.AddTransition(WAITING_FOR_VERIFICATION_MESSAGES,
        PRIVATE_KEY_SHARING);
    _state_machine.AddTransition(PRIVATE_KEY_SHARING,
        WAITING_FOR_PRIVATE_KEYS);
  }

  void ShuffleRound::InitClient()
  {
    _state = QSharedPointer<State>(new State());

    _state_machine.AddTransition(OFFLINE,
        WAITING_FOR_PUBLIC_KEYS);
    _state_machine.AddTransition(WAITING_FOR_PUBLIC_KEYS,
        CIPHERTEXT_GENERATION);
    _state_machine.AddTransition(CIPHERTEXT_GENERATION,
        SUBMIT_CIPHERTEXT);
    _state_machine.AddTransition(SUBMIT_CIPHERTEXT,
        WAITING_FOR_ENCRYPTED_INNER_DATA);
    _state_machine.AddTransition(WAITING_FOR_ENCRYPTED_INNER_DATA,
        VERIFICATION);
#if 0
    // Ideally servers would either send back private keys or a failed message
    _state_machine.AddTransition(VERIFICATION, WAITING_FOR_PRIVATE_KEYS);
#else
    _state_machine.AddState(WAITING_FOR_VERIFICATION_MESSAGES, GO_MESSAGE,
        &ShuffleRound::HandleVerification, &ShuffleRound::PrepareForVerification);

    _state_machine.AddTransition(VERIFICATION, WAITING_FOR_VERIFICATION_MESSAGES);
    _state_machine.AddTransition(WAITING_FOR_VERIFICATION_MESSAGES,
        WAITING_FOR_PRIVATE_KEYS);
#endif
  }

  ShuffleRound::~ShuffleRound()
  {
  }

  QByteArray ShuffleRound::PrepareData()
  {
    QPair<QByteArray, bool> data = GetData(BlockSize);
    if(data.first.isEmpty()) {
      return DefaultData;
    } else if(data.first.size() > BlockSize) {
      qWarning() << "Attempted to send a data larger than the block size:" <<
        data.first.size() << ":" << BlockSize;

      return DefaultData;
    }

    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId() <<
      "Sending real data:" << data.first.size() << data.first.toBase64();

    QByteArray msg(4, 0);
    Dissent::Utils::Serialization::WriteInt(data.first.size(), msg, 0);
    msg.append(data.first);
    msg.resize(BlockSize + 4);
    return msg;
  }

  QByteArray ShuffleRound::ParseData(QByteArray data)
  {
    int size = Dissent::Utils::Serialization::ReadInt(data, 0);
    if(size == 0) {
      return QByteArray();
    }

    if(size > BlockSize || size > data.size() - 4) {
      qWarning() << "Received bad cleartext...";
      return QByteArray();
    }

    return QByteArray(data.data() + 4, size);
  }

  void ShuffleRound::OnStart()
  {
    Round::OnStart();

    _state->public_inner_keys.resize(_shufflers.Count());
    _state->public_outer_keys.resize(_shufflers.Count());

    _state_machine.StateComplete();
  }

  void ShuffleRound::OnStop()
  {
    _state_machine.SetState(FINISHED);
    Round::OnStop();
  }

  void ShuffleRound::HandlePublicKeys(const Id &id, QDataStream &stream)
  {
    int sidx = _shufflers.GetIndex(id);
    if(sidx < 0) {
      throw QRunTimeError("Received a public key message from a non-shuffler");
    }

    int kidx = CalculateKidx(sidx);
    if(_state->public_inner_keys[kidx] || _state->public_outer_keys[kidx]) {
      throw QRunTimeError("Received duplicate public keys");
    }

    QSharedPointer<AsymmetricKey> inner_key, outer_key;
    stream >> inner_key >> outer_key;

    if(!inner_key->IsValid()) {
      throw QRunTimeError("Received an invalid inner public key");
    } else if(!outer_key->IsValid()) {
      throw QRunTimeError("Received an invalid outer public key");
    }

    _state->public_inner_keys[kidx] = inner_key;
    _state->public_outer_keys[kidx] = outer_key;

    ++_state->keys_received;

    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId() <<
        ": received public keys from" << GetGroup().GetIndex(id) << id <<
        "Have:" << _state->keys_received << "expect:" << _shufflers.Count();

    if(_state->keys_received == _shufflers.Count()) {
      _state_machine.StateComplete();
    }
  }

  void ShuffleRound::HandleData(const Id &id, QDataStream &stream)
  {
    int gidx = GetGroup().GetIndex(id);
    if(!_server_state->shuffle_input[gidx].isEmpty()) {
      throw QRunTimeError("Received multiples data messages.");
    }

    QByteArray data;
    stream >> data;

    if(data.isEmpty()) {
      throw QRunTimeError("Received a null data");
    }

    _server_state->shuffle_input[gidx] = data;
    ++_server_state->data_received;

    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId() <<
        ": received initial data from" << GetGroup().GetIndex(id) << id <<
        "Have:" << _server_state->data_received << "expect:" << GetGroup().Count();

    if(_server_state->data_received == GetGroup().Count()) {
      _state_machine.StateComplete();
    }
  }

  void ShuffleRound::HandleShuffle(const Id &id, QDataStream &stream)
  {
    if(_shufflers.Previous(GetLocalId()) != id) {
      throw QRunTimeError("Received a shuffle out of order");
    }

    stream >> _server_state->shuffle_input;

    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId() <<
        ": received shuffle data from" << GetGroup().GetIndex(id) << id;

    _state_machine.StateComplete();
  }

  void ShuffleRound::HandleDataBroadcast(const Id &id, QDataStream &stream)
  {
    if(_shufflers.Last() != id) {
      throw QRunTimeError("Received data broadcast from the wrong node");
    }

    stream >> _state->encrypted_data;

    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId() <<
        ": received data broadcast from" << GetGroup().GetIndex(id) << id;

    _state_machine.StateComplete();
  }
    
  void ShuffleRound::HandleVerification(const Id &id, QDataStream &stream)
  {
    int gidx = GetGroup().GetIndex(id);
    if(_state->go.contains(gidx)) {
      throw QRunTimeError("Received multiples go messages from same identity");
    }

    bool go;
    stream >> go;

    _state->go[gidx] = go;
    if(go) {
      stream >> _state->state_hashes[gidx];
    }

    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId() <<
        ": received" << go << "from" << GetGroup().GetIndex(id) << id <<
        "Have:" << _state->go.count() << "expect:" << GetGroup().Count();

    if(_state->go.count() < GetGroup().Count()) {
      return;
    }

    for(int idx = 0; idx < GetGroup().Count(); idx++) {
      if(!_state->go[idx] ||
          (_state->state_hashes[idx] != _state->state_hash))
      {
        if(!_state->go[idx]) {
          qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId() <<
              ": starting blame due to no go from" <<
              GetGroup().GetId(idx) << idx;
        } else {
          qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId() <<
              ": starting blame mismatched state hashes" <<
              GetGroup().GetId(idx) << idx << "... Got:" <<
              _state->state_hashes[idx].toBase64() << ", expected:" <<
              _state->state_hash.toBase64();
        }

        _state_machine.SetState(BLAME_SHARE);
        return;
      }
    }

    _state_machine.StateComplete();
  }

  void ShuffleRound::HandlePrivateKey(const Id &id, QDataStream &stream)
  {
    int sidx = _shufflers.GetIndex(id);
    if(sidx < 0) {
      throw QRunTimeError("Received a private key message from a non-shuffler");
    }

    if(_state->private_inner_keys[sidx] != 0) {
      throw QRunTimeError("Received multiple private key messages from the same identity");
    }

    QSharedPointer<AsymmetricKey> key;
    stream >> key;

    if(!key->IsValid()) {
      throw QRunTimeError("Received invalid inner key");
    }

    int kidx = CalculateKidx(sidx);
    if(!key->VerifyKey(*_state->public_inner_keys[kidx])) {
      throw QRunTimeError("Received mismatched inner key");
    }

    _state->private_inner_keys[sidx] = key;
    ++_state->keys_received;

    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId() <<
        ": received private key from" << GetGroup().GetIndex(id) << 
        id << "Have:" << _state->keys_received << "expect:" << _shufflers.Count();

    if(_state->keys_received == _state->private_inner_keys.count()) {
      _state_machine.StateComplete();
    }
  }

  void ShuffleRound::HandleBlame(const Id &id, QDataStream &stream)
  {
    int gidx = GetGroup().GetIndex(id);
    if(!_state->blame_hash[gidx].isEmpty()) {
      throw QRunTimeError("Received multiple blame messages from the same identity");
    }

    Hash hashalgo;
    int sidx = _shufflers.GetIndex(id);
    QSharedPointer<AsymmetricKey> outer_key;
    if(sidx >= 0) {
      stream >> outer_key;
      hashalgo.Update(outer_key->GetByteArray());
    }

    QByteArray log, sig;
    stream >> log >> sig;

    hashalgo.Update(log);
    QByteArray blame_hash = hashalgo.ComputeHash();

    QByteArray sigmsg;
    QDataStream sigstream(&sigmsg, QIODevice::WriteOnly);
    sigstream << BLAME_DATA << GetRoundId() << blame_hash;

    if(!GetGroup().GetKey(gidx)->Verify(sigmsg, sig)) {
      throw QRunTimeError("Receiving invalid blame data");
    }

    if(sidx >= 0) {
      int kidx = CalculateKidx(sidx);
      if(!outer_key->VerifyKey(*_state->public_outer_keys[kidx])) {
        throw QRunTimeError("Invalid outer key");
      }
      _state->private_outer_keys[sidx] = outer_key;
    }

    _state->logs[gidx] = Log(log);
    _state->blame_hash[gidx] = blame_hash;
    _state->blame_signatures[gidx] = sig;
    ++_state->data_received;

    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId() <<
        ": received blame data from" << GetGroup().GetIndex(id) << id <<
        "Have:" << _state->data_received << "expect:" << GetGroup().Count();

    if(_state->data_received == GetGroup().Count()) {
      _state_machine.StateComplete();
    }
  }

  void ShuffleRound::HandleBlameVerification(const Id &id, QDataStream &stream)
  {
    int gidx = GetGroup().GetIndex(id);
    if(_state->blame_verification_msgs[gidx] != HashSig()) {
      throw QRunTimeError("Received duplicate blame verification messages.");
    }

    QVector<QByteArray> blame_hash, blame_signatures;
    stream >> blame_hash >> blame_signatures;
    if((blame_hash.count() != GetGroup().Count()) ||
        (blame_signatures.count() != GetGroup().Count()))
    {
      throw QRunTimeError("Missing signatures / hashes");
    }
    
    for(int idx = 0; idx < GetGroup().Count(); idx++) {
      QByteArray sigmsg;
      QDataStream sigstream(&sigmsg, QIODevice::WriteOnly);
      sigstream << BLAME_DATA << GetRoundId() << blame_hash[idx];
      if(!GetGroup().GetKey(idx)->Verify(sigmsg, blame_signatures[idx])) {
        throw QRunTimeError("Received an invalid blame hash, signature pair");
      }
    }

    _state->blame_verification_msgs[gidx] = HashSig(blame_hash, blame_signatures);
    ++_state->blame_verifications;

    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId() <<
        ": received blame verification from" << GetGroup().GetIndex(id) << id
        << "Have:" << _state->blame_verifications << "expect:" << GetGroup().Count();

    if(_state->blame_verifications == GetGroup().Count()) {
      _state_machine.StateComplete();
    }
  }

  void ShuffleRound::BroadcastPublicKeys()
  {
    Library &lib = CryptoFactory::GetInstance().GetLibrary();
    _server_state->inner_key = QSharedPointer<AsymmetricKey>(lib.CreatePrivateKey());
    _server_state->outer_key = QSharedPointer<AsymmetricKey>(lib.CreatePrivateKey());

    QSharedPointer<AsymmetricKey> inner_key(_server_state->inner_key->GetPublicKey());
    QSharedPointer<AsymmetricKey> outer_key(_server_state->outer_key->GetPublicKey());

    QByteArray msg;
    QDataStream stream(&msg, QIODevice::WriteOnly);
    stream << PUBLIC_KEYS << GetRoundId() << inner_key << outer_key;

    VerifiableBroadcast(msg);
    _state_machine.StateComplete();
  }

  void ShuffleRound::GenerateCiphertext()
  {
    OnionEncryptor &oe = CryptoFactory::GetInstance().GetOnionEncryptor();
    // XXX Put in another thread
    oe.Encrypt(_state->public_inner_keys, PrepareData(), _state->inner_ciphertext, 0);
    oe.Encrypt(_state->public_outer_keys, _state->inner_ciphertext, _state->outer_ciphertext, 0);

    _state_machine.StateComplete();
  }

  void ShuffleRound::SubmitCiphertext()
  {
    QByteArray msg;
    QDataStream stream(&msg, QIODevice::WriteOnly);
    stream << DATA << GetRoundId() << _state->outer_ciphertext;

    VerifiableSend(_shufflers.GetId(0), msg);
    _state_machine.StateComplete();
  }

  void ShuffleRound::PrepareForInitialData()
  {
    _server_state->shuffle_input = QVector<QByteArray>(GetGroup().Count());
  }

  void ShuffleRound::Shuffle()
  {
    for(int idx = 0; idx < _server_state->shuffle_input.count(); idx++) {
      for(int jdx = 0; jdx < _server_state->shuffle_input.count(); jdx++) {
        if(idx == jdx) {
          continue;
        }
        if(_server_state->shuffle_input[idx] != _server_state->shuffle_input[jdx]) {
          continue;
        }
        qWarning() << "Found duplicate cipher texts... setting blame";
        _state->blame = true;
        break;
      }
    }

    QVector<int> bad;
    OnionEncryptor &oe = CryptoFactory::GetInstance().GetOnionEncryptor();
    if(!oe.Decrypt(_server_state->outer_key, _server_state->shuffle_input,
          _server_state->shuffle_output, &bad))
    {
      qWarning() << _shufflers.GetIndex(GetLocalId()) <<
        GetGroup().GetIndex(GetLocalId()) << GetLocalId() <<
        ": failed to decrypt layer due to block at indexes" << bad;
      _state->blame = true;
    }

    oe.RandomizeBlocks(_server_state->shuffle_output);

    const Id &next = _shufflers.Next(GetLocalId());
    MessageType mtype = (next == Id::Zero()) ? ENCRYPTED_DATA : SHUFFLE_DATA;

    QByteArray msg;
    QDataStream out_stream(&msg, QIODevice::WriteOnly);
    out_stream << mtype << GetRoundId() << _server_state->shuffle_output;

    if(mtype == ENCRYPTED_DATA) {
      VerifiableBroadcast(msg);
    } else {
      VerifiableSend(next, msg);
    }

    _state_machine.StateComplete();
  }

  void ShuffleRound::VerifyInnerCiphertext()
  {
    bool found = !_state->blame &&
      _state->encrypted_data.contains(_state->inner_ciphertext);

    QByteArray msg;
    QDataStream out_stream(&msg, QIODevice::WriteOnly);
    out_stream << GO_MESSAGE << GetRoundId() << found;

    if(found) {
      Hash hashalgo;
      for(int idx = 0; idx < _state->public_inner_keys.count(); idx++) {
        hashalgo.Update(_state->public_inner_keys[idx]->GetByteArray());
        hashalgo.Update(_state->public_outer_keys[idx]->GetByteArray());
        hashalgo.Update(_state->encrypted_data[idx]);
      }
      _state->state_hash = hashalgo.ComputeHash();
      out_stream << _state->state_hash;

      qDebug() << _shufflers.GetIndex(GetLocalId()) <<
        GetGroup().GetIndex(GetLocalId()) <<
        ": found our data in the shuffled ciphertexts";
    } else {
      qWarning() << _shufflers.GetIndex(GetLocalId()) <<
        GetGroup().GetIndex(GetLocalId()) <<
        "Did not find our message in the shuffled ciphertexts!";
    }

    VerifiableBroadcast(msg);
    _state_machine.StateComplete();
  }

  void ShuffleRound::BroadcastPrivateKey()
  {
    qDebug() << _shufflers.GetIndex(GetLocalId()) <<
      GetGroup().GetIndex(GetLocalId()) << GetLocalId()
      << ": received sufficient go messages, broadcasting private key.";

    QByteArray msg;
    QDataStream stream(&msg, QIODevice::WriteOnly);
    stream << PRIVATE_KEY << GetRoundId() << _server_state->inner_key;

    VerifiableBroadcast(msg);
    _state_machine.StateComplete();
  }
  
  void ShuffleRound::PrepareForPrivateKeys()
  {
    _state->keys_received = 0;
    _state->private_inner_keys.resize(_shufflers.Count());
    _state->private_outer_keys.resize(_shufflers.Count());
  }

  void ShuffleRound::PrepareForVerification()
  {
    _state->state_hashes = QVector<QByteArray>(GetGroup().Count());
  }

  void ShuffleRound::Decrypt()
  {
    Decryptor *decryptor = new Decryptor(_state->private_inner_keys, _state->encrypted_data);
    QObject::connect(decryptor,
        SIGNAL(Finished(const QVector<QByteArray> &, const QVector<int> &)),
        this,
        SLOT(DecryptDone(const QVector<QByteArray> &, const QVector<int> &)), Qt::QueuedConnection);
    QThreadPool::globalInstance()->start(decryptor);
  }

  void ShuffleRound::DecryptDone(const QVector<QByteArray> &cleartexts,
      const QVector<int> &bad)
  {
    if(!bad.isEmpty()) {
      qWarning() << GetGroup().GetIndex(GetLocalId()) << GetLocalId() <<
        ": failed to decrypt final layers due to block at index" << bad;
      Stop("Round unsuccessfully finished.");
    }

    foreach(const QByteArray &cleartext, cleartexts) {
      QByteArray msg = ParseData(cleartext);
      if(msg.isEmpty()) {
        continue;
      }
      qDebug() << GetLocalId() << "received a valid message: " << msg.size()
        << msg.toBase64();
      PushData(GetSharedPointer(), msg);
    }
    SetSuccessful(true);
    Stop("Round finished successfully");
  }

  void ShuffleRound::StartBlame()
  {
    QByteArray msg;
    QDataStream stream(&msg, QIODevice::WriteOnly);
    stream << BLAME_DATA << GetRoundId();

    Hash hashalgo;
    if(_server_state) {
      stream << _server_state->outer_key;
      hashalgo.Update(_server_state->outer_key->GetByteArray());
    }

    QByteArray log = _state_machine.GetLog().Serialize();
    stream << log;
    hashalgo.Update(log);

    QByteArray sigmsg;
    QDataStream sigstream(&sigmsg, QIODevice::WriteOnly);
    sigstream << BLAME_DATA << GetRoundId() << hashalgo.ComputeHash();

    QByteArray signature = GetSigningKey()->Sign(sigmsg);
    stream << signature;
    
    int ccount = GetGroup().Count();
    int scount = GetGroup().GetSubgroup().Count();
    _state->data_received = 0;
    _state->blame_hash = QVector<QByteArray>(ccount);
    _state->private_outer_keys = QVector<QSharedPointer<AsymmetricKey> >(scount);
    _state->logs = QVector<Log>(ccount);
    _state->blame_signatures = QVector<QByteArray>(ccount);

    VerifiableBroadcast(msg);
  }

  void ShuffleRound::BroadcastBlameVerification()
  {
    QByteArray msg;
    QDataStream stream(&msg, QIODevice::WriteOnly);
    stream << BLAME_VERIFICATION << GetRoundId() << _state->blame_hash
      << _state->blame_signatures;

    _state->blame_verification_msgs = QVector<HashSig>(GetGroup().Count());

    VerifiableBroadcast(msg);
  }

  void ShuffleRound::BlameRound()
  {
    for(int idx = 0; idx < GetGroup().Count(); idx++ ) {
      HashSig blame_ver = _state->blame_verification_msgs[idx];
      QVector<QByteArray> blame_hash = blame_ver.first;

      for(int jdx = 0; jdx < GetGroup().Count(); jdx++) {
        if(blame_hash[jdx] == _state->blame_hash[jdx]) {
          continue;
        }

        qWarning() << "Bad nodes: " << idx;
        _state->bad_members.append(idx);
      }
    }

    if(_state->bad_members.count() == 0) {
      ShuffleBlamer sb(GetGroup(), GetRoundId(), _state->logs,
          _state->private_outer_keys);
      sb.Start();
      for(int idx = 0; idx < sb.GetBadNodes().count(); idx++) {
        if(sb.GetBadNodes()[idx]) {
          qWarning() << "Bad nodes: " << idx;
          _state->bad_members.append(idx);
        }
      }
    }
    Stop("Round caused blame and finished unsuccessfully.");
  }

namespace ShuffleRoundPrivate {
  void Decryptor::run()
  {
    QVector<QByteArray> cleartexts = _encrypted_data;

    foreach(const QSharedPointer<AsymmetricKey> &key, _keys) {
      QVector<QByteArray> tmp;
      QVector<int> bad;

      OnionEncryptor &oe = CryptoFactory::GetInstance().GetOnionEncryptor();

      if(!oe.Decrypt(key, cleartexts, tmp, &bad)) {
        emit Finished(QVector<QByteArray>(), bad);
        return;
      }

      cleartexts = tmp;
    }

    emit Finished(cleartexts, QVector<int>());
  }
}
}
}
