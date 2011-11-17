#include "../Utils/Serialization.hpp"
#include "ShuffleRound.hpp"
#include "ShuffleBlamer.hpp"

namespace Dissent {
namespace Anonymity {
  const QByteArray ShuffleRound::DefaultData = QByteArray(ShuffleRound::BlockSize + 4, 0);

  ShuffleRound::ShuffleRound(const Group &group, const Group &shufflers,
      const Id &local_id, const Id &session_id, const Id &round_id,
      const ConnectionTable &ct, RpcHandler &rpc,
      QSharedPointer<AsymmetricKey> signing_key, const QByteArray &data) :
    Round(group, shufflers, local_id, session_id, round_id, ct, rpc,
        signing_key, data),
    _shuffler(GetActiveGroup().Contains(local_id)),
    _state(Offline),
    _blame_state(Offline),
    _public_inner_keys(GetActiveGroup().Count()),
    _public_outer_keys(GetActiveGroup().Count()),
    _keys_received(0),
    _private_inner_keys(GetActiveGroup().Count()),
    _private_outer_keys(GetActiveGroup().Count()),
    _data_received(0),
    _go_count(0),
    _go_received(GetGroup().Count(), false),
    _go(GetGroup().Count(), false),
    _broadcast_hashes(GetGroup().Count()),
    _blame_received(GetGroup().Count(), false),
    _logs(group.Count()),
    _blame_hash(GetGroup().Count()),
    _blame_signatures(GetGroup().Count()),
    _valid_blames(GetGroup().Count(), false),
    _received_blame_verification(GetGroup().Count(), false)
  {
    if(_shuffler) {
      Library *lib = CryptoFactory::GetInstance().GetLibrary();
      _inner_key.reset(lib->CreatePrivateKey());
      _outer_key.reset(lib->CreatePrivateKey());
    }

    if(GetActiveGroup().GetIndex(GetLocalId()) == 0) {
      _shuffle_ciphertext = QVector<QByteArray>(GetGroup().Count());
    }
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
    if(GetData() == DefaultData) {
      return DefaultData;
    } else if(GetData().size() > BlockSize) {
      qWarning() << "Attempted to send a data larger than the block size:" <<
        GetData().size() << ":" << BlockSize;

      return DefaultData;
    }

    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
      "Sending real data:" << GetData().size() << GetData().toBase64();

    QByteArray msg(4, 0);
    Dissent::Utils::Serialization::WriteInt(GetData().size(), msg, 0);
    msg.append(GetData());
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

  void ShuffleRound::Broadcast(const QByteArray &data)
  {
    QByteArray msg = data + GetSigningKey()->Sign(data);
    Round::Broadcast(msg);
    ProcessData(msg, GetLocalId());
  }

  void ShuffleRound::Send(const QByteArray &data, const Id &id)
  {
    QByteArray msg = data + GetSigningKey()->Sign(data);

    if(id == GetLocalId()) {
      ProcessData(msg, id);
      return;
    }

    Round::Send(msg, id);
  }

  bool ShuffleRound::Start()
  {
    if(!Round::Start()) {
      qWarning() << "Called start on ShuffleRound more than once.";
      return false;
    }

    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
      ": starting:" << ToString();

    BroadcastPublicKeys();
    return true;
  }

  void ShuffleRound::HandlePublicKeys(QDataStream &stream, const Id &id)
  {
    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
        ": received public keys from " << GetGroup().GetIndex(id) << id.ToString();

    if(_state != Offline && _state != KeySharing) {
      throw QRunTimeError("Received a misordered key message");
    }

    int sidx = GetActiveGroup().GetIndex(id);
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

    if(++_keys_received == GetActiveGroup().Count()) {
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

    int sidx = GetActiveGroup().GetIndex(GetLocalId());
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

    if(GetGroup().Previous(GetLocalId()) != id) {
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

    if(GetActiveGroup().Count() - 1 != GetActiveGroup().GetIndex(id)) {
      throw QRunTimeError("Received data broadcast from the wrong node");
    }

    stream >> _encrypted_data;
    Verify();
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

    int sidx = GetActiveGroup().GetIndex(id);
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

    int sidx = GetActiveGroup().GetIndex(id);
    QByteArray key;
    if(sidx >= 0) {
      stream >> key;
      hashalgo->Update(key);
    }

    QByteArray log, sig;
    stream >> log >> sig;

    hashalgo->Update(log);

    QByteArray sigmsg;
    QDataStream sigstream(&sigmsg, QIODevice::WriteOnly);
    sigstream << BlameData << GetRoundId().GetByteArray() << hashalgo->ComputeHash();

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
    _blame_hash[gidx] = sigmsg;
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

    int gidx = GetGroup().GetIndex(id);
    if(_received_blame_verification[gidx]) {
      throw QRunTimeError("Received duplicate blame verification messages.");
    }

    QVector<QByteArray> blame_hash, blame_signatures;
    stream >> blame_hash >> blame_signatures;
    if(blame_hash.count() != GetGroup().Count() || blame_signatures.count() != GetGroup().Count()) {
      throw QRunTimeError("Missing signatures / hashes");
    }

    for(int jdx = 0; jdx < GetGroup().Count(); jdx++) {
      if(blame_hash[jdx] == _blame_hash[jdx]) {
        continue;
      }

      QByteArray sigmsg;
      QDataStream sigstream(&sigmsg, QIODevice::WriteOnly);
      sigstream << BlameData << GetRoundId().GetByteArray() << blame_hash[jdx];
      if(!GetGroup().GetKey(gidx)->Verify(sigmsg, blame_signatures[jdx])) {
        throw QRunTimeError("Received invalid hash / signature");
      }
      _valid_blames[jdx] = true;
    }

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
        "in session / round" << GetRoundId().ToString() << GetId().ToString()
        << "in state" << StateToString(_state) <<
        "causing the following exception: " << err.What();
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

  bool ShuffleRound::Verify(const QByteArray &data, QByteArray &msg, const Id &id)
  {
    QSharedPointer<AsymmetricKey> key = GetGroup().GetKey(id);
    if(key.isNull()) {
      throw QRunTimeError("Received malsigned data block, no such peer");
    }

    int sig_size = key->GetKeySize() / 8;
    if(data.size() < sig_size) {
      QString error = QString("Received malsigned data block, not enough "
          "data blocks. Expected at least: %1 got %2").arg(sig_size).arg(data.size());
      throw QRunTimeError(error);
    }

    msg = QByteArray::fromRawData(data.data(), data.size() - sig_size);
    QByteArray sig = QByteArray::fromRawData(data.data() + msg.size(), sig_size);
    return key->Verify(msg, sig);
  }

  void ShuffleRound::BroadcastPublicKeys()
  {
    if(_state == Offline) {
      _state = KeySharing;
    }

    if(!_shuffler) {
      qDebug() << GetActiveGroup().GetIndex(GetLocalId()) << GetGroup().GetIndex(GetLocalId())
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

    qDebug() << GetActiveGroup().GetIndex(GetLocalId()) << GetGroup().GetIndex(GetLocalId())
      << ": key shared waiting for other keys.";

    Broadcast(msg);
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

    qDebug() << GetActiveGroup().GetIndex(GetLocalId()) << GetGroup().GetIndex(GetLocalId())
      << ": data submitted now in state:" << StateToString(_state);

    Send(msg, GetActiveGroup().GetId(0));
  }

  void ShuffleRound::Shuffle()
  {
    _state = Shuffling;
    qDebug() << GetActiveGroup().GetIndex(GetLocalId()) << GetGroup().GetIndex(GetLocalId())
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
      qWarning() << GetActiveGroup().GetIndex(GetLocalId()) << GetGroup().GetIndex(GetLocalId())
        << GetLocalId().ToString() << ": failed to decrypt layer due to block at "
        "indexes" << bad;
      StartBlame();
      return;
    }

    oe->RandomizeBlocks(_shuffle_cleartext);

    const Id &next = GetActiveGroup().Next(GetLocalId());
    MessageType mtype = (next == Id::Zero) ? EncryptedData : ShuffleData;

    QByteArray msg;
    QDataStream out_stream(&msg, QIODevice::WriteOnly);
    out_stream << mtype << GetRoundId().GetByteArray() << _shuffle_cleartext;

    _state = WaitingForEncryptedInnerData;

    qDebug() << GetActiveGroup().GetIndex(GetLocalId()) << GetGroup().GetIndex(GetLocalId())
      << ": finished shuffling";

    if(mtype == EncryptedData) {
      Broadcast(msg);
    } else {
      Send(msg, next);
    }
  }

  void ShuffleRound::Verify()
  {
    bool found = _encrypted_data.contains(_inner_ciphertext);
    if(found) {
      _state = Verification;
    } else {
      qWarning() << GetActiveGroup().GetIndex(GetLocalId()) <<
        GetGroup().GetIndex(GetLocalId()) <<
        "Did not find our message in the shuffled ciphertexts!";
    }

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

      qDebug() << GetActiveGroup().GetIndex(GetLocalId()) <<
        GetGroup().GetIndex(GetLocalId()) <<
        ": found our data in the shuffled ciphertexts";
    }

    Broadcast(msg);
  }

  void ShuffleRound::BroadcastPrivateKey()
  {
    _state = PrivateKeySharing;

    if(!_shuffler) {
      qDebug() << GetActiveGroup().GetIndex(GetLocalId()) <<
        GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
        ": received sufficient go messages, waiting for keys.";
      return;
    }

    qDebug() << GetActiveGroup().GetIndex(GetLocalId()) <<
      GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString()
      << ": received sufficient go messages, broadcasting private key.";

    QByteArray msg;
    QDataStream stream(&msg, QIODevice::WriteOnly);
    stream << PrivateKey << GetRoundId().GetByteArray() << _inner_key->GetByteArray();

    Broadcast(msg);
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
    
    Broadcast(msg);
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

    Broadcast(msg);
  }

  void ShuffleRound::BlameRound()
  {
    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
        ": entering blame round.";

    for(int idx = 0; idx < _valid_blames.count(); idx++) {
      if(_valid_blames[idx]) {
        qWarning() << "Bad nodes: " << idx;
        _bad_members.append(idx);
      }
    }

    if(_bad_members.count() > 0) {
      return;
    }

    ShuffleBlamer sb(GetGroup(), GetActiveGroup(), GetId(), GetRoundId(), _logs,
        _private_outer_keys);
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
