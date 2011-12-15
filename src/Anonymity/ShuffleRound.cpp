#include "../Crypto/CryptoFactory.hpp"
#include "../Utils/Serialization.hpp"
#include "../Utils/QRunTimeError.hpp"

#include "ShuffleRound.hpp"
#include "ShuffleBlamer.hpp"

using Dissent::Crypto::CryptoFactory;
using Dissent::Crypto::Hash;
using Dissent::Crypto::Library;
using Dissent::Crypto::OnionEncryptor;
using Dissent::Utils::QRunTimeError;

namespace Dissent {
namespace Anonymity {
  const QByteArray ShuffleRound::DefaultData = QByteArray(ShuffleRound::BlockSize + 4, 0);

  ShuffleRound::ShuffleRound(const Group &group,
      const Credentials &creds, const Id &round_id,
      QSharedPointer<Network> network, GetDataCallback &get_data) :
    Round(group, creds, round_id, network, get_data),
    _shufflers(GetGroup().GetSubgroup()),
    _shuffler(_shufflers.Contains(GetLocalId())),
    _state(Offline),
    _blame_state(Offline),
    _keys_received(0),
    _data_received(0),
    _go_count(0),
    _go_received(GetGroup().Count(), false),
    _go(GetGroup().Count(), false),
    _broadcast_hashes(GetGroup().Count()),
    _blame_received(GetGroup().Count(), false),
    _logs(GetGroup().Count()),
    _blame_hash(GetGroup().Count()),
    _blame_signatures(GetGroup().Count()),
    _received_blame_verification(GetGroup().Count(), false)
  {
  }

  ShuffleRound::~ShuffleRound()
  {
    DeleteKeys(_public_inner_keys);
    DeleteKeys(_public_outer_keys);
    DeleteKeys(_private_inner_keys);
    DeleteKeys(_private_outer_keys);
  }

  void ShuffleRound::DeleteKeys(QVector<AsymmetricKey *> &keys)
  {
    foreach(AsymmetricKey *key, keys) {
      if(key) {
        delete key;
      }
    }
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

    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
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

  bool ShuffleRound::Start()
  {
    if(!Round::Start()) {
      qWarning() << "Called start on ShuffleRound more than once.";
      return false;
    }

    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
      ": starting:" << ToString();

    if(_shuffler) {
      Library *lib = CryptoFactory::GetInstance().GetLibrary();
      _inner_key.reset(lib->CreatePrivateKey());
      _outer_key.reset(lib->CreatePrivateKey());
      if(_shufflers.GetIndex(GetLocalId()) == 0) {
        _shuffle_ciphertext = QVector<QByteArray>(GetGroup().Count());
      }
    }

    _public_inner_keys.resize(_shufflers.Count());
    _public_outer_keys.resize(_shufflers.Count());
    _private_inner_keys.resize(_shufflers.Count());
    _private_outer_keys.resize(_shufflers.Count());

    BroadcastPublicKeys();

    Id from(Id::Zero());
    QByteArray entry(0);

    for(int idx = 0; idx < _offline_log.Count(); idx++) {
      QPair<QByteArray, Id> entry = _offline_log.At(idx);
      ProcessData(entry.first, entry.second);
    }

    _offline_log.Clear();

    return true;
  }

  void ShuffleRound::HandlePublicKeys(QDataStream &stream, const Id &id)
  {
    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
        ": received public keys from " << GetGroup().GetIndex(id) << id.ToString();

    if(_state != KeySharing) {
      throw QRunTimeError("Received a misordered key message");
    }

    int sidx = _shufflers.GetIndex(id);
    if(sidx < 0) {
      throw QRunTimeError("Received a public key message from a non-shuffler");
    }

    int kidx = CalculateKidx(sidx);
    if(_public_inner_keys[kidx] != 0 || _public_outer_keys[kidx] != 0) {
      throw QRunTimeError("Received duplicate public keys");
    }

    QByteArray inner_key, outer_key;
    stream >> inner_key >> outer_key;

    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    _public_inner_keys[kidx] = lib->LoadPublicKeyFromByteArray(inner_key);
    _public_outer_keys[kidx] = lib->LoadPublicKeyFromByteArray(outer_key);

    if(!_public_inner_keys[kidx]->IsValid()) {
      throw QRunTimeError("Received an invalid outer inner key");
    } else if(!_public_outer_keys[kidx]->IsValid()) {
      throw QRunTimeError("Received an invalid outer public key");
    }

    if(++_keys_received == _shufflers.Count()) {
      _keys_received = 0;
      SubmitData();
    }
  }

  void ShuffleRound::HandleData(QDataStream &stream, const Id &id)
  {
    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
        ": received initial data from " << GetGroup().GetIndex(id) << id.ToString();

    if(_state != KeySharing && _state != DataSubmission &&
        _state != WaitingForShuffle)
    {
      throw QRunTimeError("Received a misordered data message");
    }

    int sidx = _shufflers.GetIndex(GetLocalId());
    if(sidx != 0) {
      throw QRunTimeError("Received a data message while not the first"
          " node in the group");
    }

    QByteArray data;
    stream >> data;

    int gidx = GetGroup().GetIndex(id);

    if(data.isEmpty()) {
      throw QRunTimeError("Received a null data");
    }

    if(!_shuffle_ciphertext[gidx].isEmpty()) {
      if(_shuffle_ciphertext[gidx] != data) {
        throw QRunTimeError("Received a unique second data message");
      } else {
        throw QRunTimeError("Received multiples data messages from same identity");
      }
    }

    _shuffle_ciphertext[gidx] = data;

    if(++_data_received == GetGroup().Count()) {
      _data_received = 0;
      Shuffle();
    }
  }

  void ShuffleRound::HandleShuffle(QDataStream &stream, const Id &id)
  {
    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
        ": received shuffle data from " << GetGroup().GetIndex(id) << id.ToString();

    if(_state != WaitingForShuffle) {
      throw QRunTimeError("Received a misordered shuffle message");
    }

    if(_shufflers.Previous(GetLocalId()) != id) {
      throw QRunTimeError("Received a shuffle out of order");
    }

    stream >> _shuffle_ciphertext;

    Shuffle();
  }

  void ShuffleRound::HandleDataBroadcast(QDataStream &stream, const Id &id)
  {
    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
        ": received data broadcast from " << GetGroup().GetIndex(id) << id.ToString();

    if(_state != WaitingForEncryptedInnerData) {
      throw QRunTimeError("Received a misordered data broadcast");
    }

    if(_shufflers.Count() - 1 != _shufflers.GetIndex(id)) {
      throw QRunTimeError("Received data broadcast from the wrong node");
    }

    stream >> _encrypted_data;
    VerifyInnerCiphertext();
  }
    
  void ShuffleRound::HandleVerification(QDataStream &stream, bool go, const Id &id)
  {
    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
        ": received" << go << " from " << GetGroup().GetIndex(id)
        << id.ToString();

    if(_state != Verification && _state != WaitingForEncryptedInnerData) {
      throw QRunTimeError("Received a misordered Go / NoGo message");
    }

    int gidx = GetGroup().GetIndex(id);
    if(_go_received[gidx]) {
      throw QRunTimeError("Received multiples go messages from same identity");
    }

    _go_received[gidx] = true;
    _go[gidx] = go;
    if(go) {
      stream >> _broadcast_hashes[gidx];
    }

    if(++_go_count < GetGroup().Count()) {
      return;
    }

    for(int idx = 0; idx < GetGroup().Count(); idx++) {
      if(!_go[idx] || _broadcast_hashes[idx] != _broadcast_hash) {
        if(!_go[idx]) {
          qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
              ": starting blame due to no go from" <<
              GetGroup().GetId(idx).ToString() << idx;
        } else {
          qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
              ": starting blame mismatched broadcast hashes" <<
              GetGroup().GetId(idx).ToString() << idx << "... Got:" <<
              _broadcast_hashes[idx].toBase64() << ", expected:" <<
              _broadcast_hash.toBase64();
        }

        StartBlame();
        return;
      }
    }
    BroadcastPrivateKey();
  }

  void ShuffleRound::HandlePrivateKey(QDataStream &stream, const Id &id)
  {
    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
        ": received private key from " << GetGroup().GetIndex(id) << 
        id.ToString() << ", received" << _keys_received << "keys.";

    if(_state != Verification && _state != PrivateKeySharing) {
      throw QRunTimeError("Received misordered private key message");
    }

    int sidx = _shufflers.GetIndex(id);
    if(sidx < 0) {
      throw QRunTimeError("Received a private key message from a non-shuffler");
    }

    if(_private_inner_keys[sidx] != 0) {
      throw QRunTimeError("Received multiple private key messages from the same identity");
    }

    QByteArray key;
    stream >> key;
    int kidx = CalculateKidx(sidx);

    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    _private_inner_keys[sidx] = lib->LoadPrivateKeyFromByteArray(key);

    if(!_private_inner_keys[sidx]->VerifyKey(*_public_inner_keys[kidx])) {
      throw QRunTimeError("Received invalid inner key");
    }

    if(++_keys_received == _private_inner_keys.count()) {
      _keys_received = 0;
      Decrypt();
    }
  }

  void ShuffleRound::HandleBlame(QDataStream &stream, const Id &id)
  {
    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
        ": received blame data from " << GetGroup().GetIndex(id) << 
        id.ToString() << ", received" << _data_received << "messages.";

    int gidx = GetGroup().GetIndex(id);
    if(_blame_received[gidx]) {
      throw QRunTimeError("Received multiple blame messages from the same identity");
    }

    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QScopedPointer<Hash> hashalgo(lib->GetHashAlgorithm());;

    int sidx = _shufflers.GetIndex(id);
    QByteArray key;
    if(sidx >= 0) {
      stream >> key;
      hashalgo->Update(key);
    }

    QByteArray log, sig;
    stream >> log >> sig;

    hashalgo->Update(log);
    QByteArray blame_hash = hashalgo->ComputeHash();

    QByteArray sigmsg;
    QDataStream sigstream(&sigmsg, QIODevice::WriteOnly);
    sigstream << BlameData << GetRoundId().GetByteArray() << blame_hash;

    if(!GetGroup().GetKey(gidx)->Verify(sigmsg, sig)) {
      throw QRunTimeError("Receiving invalid blame data");
    }

    if(sidx >= 0) {
      _private_outer_keys[sidx] = lib->LoadPrivateKeyFromByteArray(key);
      int kidx = CalculateKidx(sidx);
      if(!_private_outer_keys[sidx]->VerifyKey(*_public_outer_keys[kidx])) {
        throw QRunTimeError("Invalid outer key");
      }
    }

    _blame_received[gidx] = true;
    _logs[gidx] = Log(log);
    _blame_hash[gidx] = blame_hash;
    _blame_signatures[gidx] = sig;
    ++_data_received;

    if(_state == Verification) {
      return;
    }

    if(_data_received == GetGroup().Count()) {
      BroadcastBlameVerification();
    } else if(_state != BlameInit) {
      StartBlame();
    }
  }

  void ShuffleRound::HandleBlameVerification(QDataStream &stream, const Id &id)
  {
    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
        ": received blame verification from " << GetGroup().GetIndex(id) << 
        id.ToString() << ", received" << _blame_verifications << "messages.";

    if(_state != BlameInit && _state != BlameShare) {
      throw QRunTimeError("Received a misordered blame verification message");
    }

    int gidx = GetGroup().GetIndex(id);
    if(_received_blame_verification[gidx]) {
      throw QRunTimeError("Received duplicate blame verification messages.");
    }

    QVector<QByteArray> blame_hash, blame_signatures;
    stream >> blame_hash >> blame_signatures;
    if(blame_hash.count() != GetGroup().Count() || blame_signatures.count() != GetGroup().Count()) {
      throw QRunTimeError("Missing signatures / hashes");
    }
    
    _blame_verification_msgs[gidx] = HashSig(blame_hash, blame_signatures);
    QVector<QPair<QVector<QByteArray>, QVector<QByteArray> > >(GetGroup().Count());

    _received_blame_verification[gidx] = true;
    if(++_blame_verifications == GetGroup().Count()) {
      BlameRound();
    }
  }

  void ShuffleRound::ProcessData(const QByteArray &data, const Id &from)
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

  void ShuffleRound::ProcessDataBase(const QByteArray &data, const Id &from)
  {
    QByteArray payload;
    if(!Verify(data, payload, from)) {
      throw QRunTimeError("Invalid signature or data");
    }

    if(_state == Offline) {
      _log.Pop();
      _offline_log.Append(data, from);
      return;
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

    switch(msg_type) {
      case PublicKeys:
        HandlePublicKeys(stream, from);
        break;
      case Data:
        HandleData(stream, from);
        break;
      case ShuffleData:
        HandleShuffle(stream, from);
        break;
      case EncryptedData:
        HandleDataBroadcast(stream, from);
        break;
      case GoMessage:
        HandleVerification(stream, true, from);
        break;
      case NoGoMessage:
        HandleVerification(stream, false, from);
        break;
      case PrivateKey:
        HandlePrivateKey(stream, from);
        break;
      case BlameData:
        HandleBlame(stream, from);
        break;
      case BlameVerification:
        HandleBlameVerification(stream, from);
        break;
      default:
        throw QRunTimeError("Unknown message type");
    }
  }

  void ShuffleRound::BroadcastPublicKeys()
  {
    if(_state == Offline) {
      _state = KeySharing;
    }

    if(!_shuffler) {
      qDebug() << _shufflers.GetIndex(GetLocalId()) << GetGroup().GetIndex(GetLocalId())
        << ": not sharing a key, waiting for keys.";
      return;
    }

    QScopedPointer<AsymmetricKey> in_key(_inner_key->GetPublicKey());
    QScopedPointer<AsymmetricKey> out_key(_outer_key->GetPublicKey());
    QByteArray inner_key = in_key->GetByteArray();
    QByteArray outer_key = out_key->GetByteArray();

    QByteArray msg;
    QDataStream stream(&msg, QIODevice::WriteOnly);
    stream << PublicKeys << GetRoundId().GetByteArray() << inner_key << outer_key;

    qDebug() << _shufflers.GetIndex(GetLocalId()) << GetGroup().GetIndex(GetLocalId())
      << ": key shared waiting for other keys.";

    VerifiableBroadcast(msg);
  }

  void ShuffleRound::SubmitData()
  {
    _state = DataSubmission;

    OnionEncryptor *oe = CryptoFactory::GetInstance().GetOnionEncryptor();
    oe->Encrypt(_public_inner_keys, PrepareData(), _inner_ciphertext, 0);
    oe->Encrypt(_public_outer_keys, _inner_ciphertext, _outer_ciphertext, 0);


    QByteArray msg;
    QDataStream stream(&msg, QIODevice::WriteOnly);
    stream << Data << GetRoundId().GetByteArray() << _outer_ciphertext;

    if(_shuffler) {
      _state = WaitingForShuffle;
    } else {
      _state = WaitingForEncryptedInnerData;
    }

    qDebug() << _shufflers.GetIndex(GetLocalId()) << GetGroup().GetIndex(GetLocalId())
      << ": data submitted now in state:" << StateToString(_state);

    VerifiableSend(msg, _shufflers.GetId(0));
  }

  void ShuffleRound::Shuffle()
  {
    _state = Shuffling;
    qDebug() << _shufflers.GetIndex(GetLocalId()) << GetGroup().GetIndex(GetLocalId())
      << ": shuffling";

    for(int idx = 0; idx < _shuffle_ciphertext.count(); idx++) {
      for(int jdx = 0; jdx < _shuffle_ciphertext.count(); jdx++) {
        if(idx == jdx) {
          continue;
        }
        if(_shuffle_ciphertext[idx] != _shuffle_ciphertext[jdx]) {
          continue;
        }
        qWarning() << "Found duplicate cipher texts... blaming";
        StartBlame();
        return;
      }
    }

    QVector<int> bad;
    OnionEncryptor *oe = CryptoFactory::GetInstance().GetOnionEncryptor();
    if(!oe->Decrypt(_outer_key.data(), _shuffle_ciphertext, _shuffle_cleartext, &bad)) {
      qWarning() << _shufflers.GetIndex(GetLocalId()) << GetGroup().GetIndex(GetLocalId())
        << GetLocalId().ToString() << ": failed to decrypt layer due to block at "
        "indexes" << bad;
      StartBlame();
      return;
    }

    oe->RandomizeBlocks(_shuffle_cleartext);

    const Id &next = _shufflers.Next(GetLocalId());
    MessageType mtype = (next == Id::Zero()) ? EncryptedData : ShuffleData;

    QByteArray msg;
    QDataStream out_stream(&msg, QIODevice::WriteOnly);
    out_stream << mtype << GetRoundId().GetByteArray() << _shuffle_cleartext;

    _state = WaitingForEncryptedInnerData;

    qDebug() << _shufflers.GetIndex(GetLocalId()) << GetGroup().GetIndex(GetLocalId())
      << ": finished shuffling";

    if(mtype == EncryptedData) {
      VerifiableBroadcast(msg);
    } else {
      VerifiableSend(msg, next);
    }
  }

  void ShuffleRound::VerifyInnerCiphertext()
  {
    _state = Verification;
    bool found = _encrypted_data.contains(_inner_ciphertext);

    MessageType mtype = found ?  GoMessage : NoGoMessage;
    QByteArray msg;
    QDataStream out_stream(&msg, QIODevice::WriteOnly);
    out_stream << mtype << GetRoundId().GetByteArray();

    if(found) {
      Library *lib = CryptoFactory::GetInstance().GetLibrary();
      QScopedPointer<Hash> hash(lib->GetHashAlgorithm());

      for(int idx = 0; idx < _public_inner_keys.count(); idx++) {
        hash->Update(_public_inner_keys[idx]->GetByteArray());
        hash->Update(_public_outer_keys[idx]->GetByteArray());
        hash->Update(_encrypted_data[idx]);
      }
      _broadcast_hash = hash->ComputeHash();
      out_stream << _broadcast_hash;

      qDebug() << _shufflers.GetIndex(GetLocalId()) <<
        GetGroup().GetIndex(GetLocalId()) <<
        ": found our data in the shuffled ciphertexts";
    } else {
      qWarning() << _shufflers.GetIndex(GetLocalId()) <<
        GetGroup().GetIndex(GetLocalId()) <<
        "Did not find our message in the shuffled ciphertexts!";
    }

    VerifiableBroadcast(msg);
  }

  void ShuffleRound::BroadcastPrivateKey()
  {
    _state = PrivateKeySharing;

    if(!_shuffler) {
      qDebug() << _shufflers.GetIndex(GetLocalId()) <<
        GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
        ": received sufficient go messages, waiting for keys.";
      return;
    }

    qDebug() << _shufflers.GetIndex(GetLocalId()) <<
      GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString()
      << ": received sufficient go messages, broadcasting private key.";

    QByteArray msg;
    QDataStream stream(&msg, QIODevice::WriteOnly);
    stream << PrivateKey << GetRoundId().GetByteArray() << _inner_key->GetByteArray();

    VerifiableBroadcast(msg);
  }

  void ShuffleRound::Decrypt()
  {
    _state = Decryption;

    QVector<QByteArray> cleartexts = _encrypted_data;

    foreach(AsymmetricKey *key, _private_inner_keys) {
      QVector<QByteArray> tmp;
      QVector<int> bad;

      OnionEncryptor *oe = CryptoFactory::GetInstance().GetOnionEncryptor();

      if(!oe->Decrypt(key, cleartexts, tmp, &bad)) {
        qWarning() << GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
          ": failed to decrypt final layers due to block at index" << bad;
        _state = Finished;
        Stop("Round unsuccessfully finished.");
        return;
      }

      cleartexts = tmp;
    }

    foreach(QByteArray cleartext, cleartexts) {
      QByteArray msg = ParseData(cleartext);
      if(msg.isEmpty()) {
        continue;
      }
      qDebug() << "Received a valid message: " << msg.size() << msg.toBase64();
      PushData(msg, this);
    }
    SetSuccessful(true);
    _state = Finished;

    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
        ": round finished successfully";
    Stop("Round successfully finished.");
  }

  void ShuffleRound::StartBlame()
  {
    if(_state == BlameInit) {
      qWarning() << "Already in blame state.";
      return;
    }

    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
        ": entering blame state.";

    _blame_verification_msgs = QVector<HashSig>(GetGroup().Count());

    _blame_state = _state;
    _state = BlameInit;
    _blame_verifications = 0;

    QByteArray log = _log.Serialize();
    QByteArray msg;
    QDataStream stream(&msg, QIODevice::WriteOnly);
    stream << BlameData << GetRoundId().GetByteArray();

    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QScopedPointer<Hash> hashalgo(lib->GetHashAlgorithm());;

    if(_shuffler) {
      QByteArray key = _outer_key->GetByteArray();
      stream << key;

      hashalgo->Update(key);
    }

    stream << log;
    QByteArray sigmsg;
    QDataStream sigstream(&sigmsg, QIODevice::WriteOnly);

    hashalgo->Update(log);

    sigstream << BlameData << GetRoundId().GetByteArray() << hashalgo->ComputeHash();
    QByteArray signature = GetSigningKey()->Sign(sigmsg);
    stream << signature;
    
    VerifiableBroadcast(msg);
  }

  void ShuffleRound::BroadcastBlameVerification()
  {
    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
        ": broadcasting blame state.";
    _state = BlameShare;

    QByteArray msg;
    QDataStream stream(&msg, QIODevice::WriteOnly);
    stream << BlameVerification << GetRoundId().GetByteArray() <<
      _blame_hash << _blame_signatures;

    VerifiableBroadcast(msg);
  }

  void ShuffleRound::BlameRound()
  {
    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
        ": entering blame round.";

    for(int idx = 0; idx < GetGroup().Count(); idx++ ) {
      HashSig blame_ver = _blame_verification_msgs[idx];
      QVector<QByteArray> blame_hash = blame_ver.first;
      QVector<QByteArray> blame_sig = blame_ver.second;

      for(int jdx = 0; jdx < GetGroup().Count(); jdx++) {
        if(blame_hash[jdx] == _blame_hash[jdx]) {
          continue;
        }

        QByteArray sigmsg;
        QDataStream sigstream(&sigmsg, QIODevice::WriteOnly);
        sigstream << BlameData << GetRoundId().GetByteArray() << blame_hash[jdx];
        if(!GetGroup().GetKey(jdx)->Verify(sigmsg, blame_sig[jdx])) {
          qWarning() << "Hmm" << jdx << GetGroup().GetId(jdx).ToString() << idx << GetGroup().GetId(idx).ToString();
        }

        qWarning() << "Bad nodes: " << idx;
        _bad_members.append(idx);
      }
//          throw QRunTimeError("Received invalid hash / signature from " + QString::number(jdx));
    }

    if(_bad_members.count() > 0) {
      return;
    }

    ShuffleBlamer sb(GetGroup(), GetRoundId(), _logs, _private_outer_keys);
    sb.Start();
    for(int idx = 0; idx < sb.GetBadNodes().count(); idx++) {
      if(sb.GetBadNodes()[idx]) {
        qWarning() << "Bad nodes: " << idx;
        _bad_members.append(idx);
      }
    }
    _state = Finished;
    Stop("Round caused blame and finished unsuccessfully.");
  }
}
}
