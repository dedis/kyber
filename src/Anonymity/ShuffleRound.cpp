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
    Round(group, local_id, session_id, ct, rpc),
    _shufflers(shufflers),
    _shuffler(_shufflers.Contains(local_id)),
    _round_id(round_id),
    _data(data),
    _signing_key(signing_key),
    _state(Offline),
    _blame_state(Offline),
    _public_inner_keys(_shufflers.Count()),
    _public_outer_keys(_shufflers.Count()),
    _keys_received(0),
    _private_inner_keys(_shufflers.Count()),
    _private_outer_keys(_shufflers.Count()),
    _data_received(0),
    _go_count(0),
    _go_received(_group.Count(), false),
    _go(_group.Count(), false),
    _broadcast_hashes(_group.Count()),
    _blame_received(_group.Count(), false),
    _logs(group.Count()),
    _blame_hash(_group.Count()),
    _blame_signatures(_group.Count()),
    _valid_blames(_group.Count(), false),
    _received_blame_verification(_group.Count(), false)
  {
    if(_shuffler) {
      Library *lib = CryptoFactory::GetInstance().GetLibrary();
      _inner_key.reset(lib->CreatePrivateKey());
      _outer_key.reset(lib->CreatePrivateKey());
    }

    if(data == DefaultData) {
      _data = DefaultData;
    } else if(data.size() > BlockSize) {
      qWarning() << "Attempted to send a data larger than the block size:" <<
        data.size() << ":" << BlockSize;

      _data = DefaultData;
    } else {
      qDebug() << _group.GetIndex(_local_id) << _local_id.ToString() <<
        "Sending real data:" << data.size() << data.toBase64();

      _data = PrepareData(data);
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

  QByteArray ShuffleRound::PrepareData(QByteArray data)
  {
    QByteArray msg(4, 0);
    Dissent::Utils::Serialization::WriteInt(data.size(), msg, 0);
    msg.append(data);
    msg.resize(BlockSize + 4);
    return msg;
  }

  QByteArray ShuffleRound::GetData(QByteArray data)
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
    QByteArray msg = data + _signing_key->Sign(data);
    Round::Broadcast(msg);
    ProcessData(msg, _local_id);
  }

  void ShuffleRound::Send(const QByteArray &data, const Id &id)
  {
    QByteArray msg = data + _signing_key->Sign(data);

    if(id == _local_id) {
      ProcessData(msg, id);
      return;
    }

    Round::Send(msg, id);
  }

  bool ShuffleRound::Start()
  {
    if(_state != Offline) {
      qWarning() << "Called start on ShuffleRound more than once.";
      return false;
    }

    if(_shufflers.GetIndex(_local_id) == 0) {
      _shuffle_ciphertext = QVector<QByteArray>(_group.Count());
    }

    BroadcastPublicKeys();
    return true;
  }

  void ShuffleRound::HandlePublicKeys(QDataStream &stream, const Id &id)
  {
    qDebug() << _group.GetIndex(_local_id) << _local_id.ToString() <<
        ": received public keys from " << _group.GetIndex(id) << id.ToString();

    if(_state != Offline && _state != KeySharing) {
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
    qDebug() << _group.GetIndex(_local_id) << _local_id.ToString() <<
        ": received initial data from " << _group.GetIndex(id) << id.ToString();

    if(_state != KeySharing && _state != DataSubmission &&
        _state != WaitingForShuffle)
    {
      throw QRunTimeError("Received a misordered data message");
    }

    int sidx = _shufflers.GetIndex(_local_id);
    if(sidx != 0) {
      throw QRunTimeError("Received a data message while not the first"
          " node in the group");
    }

    QByteArray data;
    stream >> data;

    int gidx = _group.GetIndex(id);

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

    if(++_data_received == _group.Count()) {
      _data_received = 0;
      Shuffle();
    }
  }

  void ShuffleRound::HandleShuffle(QDataStream &stream, const Id &id)
  {
    qDebug() << _group.GetIndex(_local_id) << _local_id.ToString() <<
        ": received shuffle data from " << _group.GetIndex(id) << id.ToString();

    if(_state != WaitingForShuffle) {
      throw QRunTimeError("Received a misordered shuffle message");
    }

    if(_group.Previous(_local_id) != id) {
      throw QRunTimeError("Received a shuffle out of order");
    }

    stream >> _shuffle_ciphertext;

    Shuffle();
  }

  void ShuffleRound::HandleDataBroadcast(QDataStream &stream, const Id &id)
  {
    qDebug() << _group.GetIndex(_local_id) << _local_id.ToString() <<
        ": received data broadcast from " << _group.GetIndex(id) << id.ToString();

    if(_state != WaitingForEncryptedInnerData) {
      throw QRunTimeError("Received a misordered data broadcast");
    }

    if(_shufflers.Count() - 1 != _shufflers.GetIndex(id)) {
      throw QRunTimeError("Received data broadcast from the wrong node");
    }

    stream >> _encrypted_data;
    Verify();
  }
    
  void ShuffleRound::HandleVerification(QDataStream &stream, bool go, const Id &id)
  {
    qDebug() << _group.GetIndex(_local_id) << _local_id.ToString() <<
        ": received" << go << " from " << _group.GetIndex(id)
        << id.ToString();

    if(_state != Verification && _state != WaitingForEncryptedInnerData) {
      throw QRunTimeError("Received a misordered Go / NoGo message");
    }

    int gidx = _group.GetIndex(id);
    if(_go_received[gidx]) {
      throw QRunTimeError("Received multiples go messages from same identity");
    }

    _go_received[gidx] = true;
    _go[gidx] = go;
    if(go) {
      stream >> _broadcast_hashes[gidx];
    }

    if(++_go_count < _group.Count()) {
      return;
    }

    for(int idx = 0; idx < _group.Count(); idx++) {
      if(!_go[idx] || _broadcast_hashes[idx] != _broadcast_hash) {
        StartBlame();
        return;
      }
    }
    BroadcastPrivateKey();
  }

  void ShuffleRound::HandlePrivateKey(QDataStream &stream, const Id &id)
  {
    qDebug() << _group.GetIndex(_local_id) << _local_id.ToString() <<
        ": received private key from " << _group.GetIndex(id) << 
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
    qDebug() << _group.GetIndex(_local_id) << _local_id.ToString() <<
        ": received blame data from " << _group.GetIndex(id) << 
        id.ToString() << ", received" << _data_received << "messages.";

    int gidx = _group.GetIndex(id);
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

    QByteArray sigmsg;
    QDataStream sigstream(&sigmsg, QIODevice::WriteOnly);
    sigstream << BlameData << _round_id.GetByteArray() << hashalgo->ComputeHash();

    if(!_group.GetKey(gidx)->Verify(sigmsg, sig)) {
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

    if(_data_received == _group.Count()) {
      BroadcastBlameVerification();
    } else if(_state != BlameInit) {
      StartBlame();
    }
  }

  void ShuffleRound::HandleBlameVerification(QDataStream &stream, const Id &id)
  {
    qDebug() << _group.GetIndex(_local_id) << _local_id.ToString() <<
        ": received blame verification from " << _group.GetIndex(id) << 
        id.ToString() << ", received" << _blame_verifications << "messages.";

    int gidx = _group.GetIndex(id);
    if(_received_blame_verification[gidx]) {
      throw QRunTimeError("Received duplicate blame verification messages.");
    }

    QVector<QByteArray> blame_hash, blame_signatures;
    stream >> blame_hash >> blame_signatures;
    if(blame_hash.count() != _group.Count() || blame_signatures.count() != _group.Count()) {
      throw QRunTimeError("Missing signatures / hashes");
    }

    for(int jdx = 0; jdx < _group.Count(); jdx++) {
      if(blame_hash[jdx] == _blame_hash[jdx]) {
        continue;
      }

      QByteArray sigmsg;
      QDataStream sigstream(&sigmsg, QIODevice::WriteOnly);
      sigstream << BlameData << _round_id.GetByteArray() << blame_hash[jdx];
      if(!_group.GetKey(gidx)->Verify(sigmsg, blame_signatures[jdx])) {
        throw QRunTimeError("Received invalid hash / signature");
      }
      _valid_blames[jdx] = true;
    }

    _received_blame_verification[gidx] = true;
    if(++_blame_verifications == _group.Count()) {
      BlameRound();
    }
  }

  void ShuffleRound::ProcessData(const QByteArray &data, const Id &from)
  {
    _log.Append(data, from);
    try {
      ProcessDataBase(data, from);
    } catch (QRunTimeError &err) {
      qWarning() << _group.GetIndex(_local_id) << _local_id.ToString() <<
        "received a message from" << _group.GetIndex(from) << from.ToString() <<
        "in session / round" << _round_id.ToString() << GetId().ToString()
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
    if(rid != _round_id) {
      throw QRunTimeError("Invalid round found");
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
    QSharedPointer<AsymmetricKey> key = _group.GetKey(id);
    if(key.isNull()) {
      throw QRunTimeError("Received malsigned data block, no such peer");
    }

    int sig_size = AsymmetricKey::KeySize / 8;
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
    _state = KeySharing;

    if(!_shuffler) {
      return;
    }

    QScopedPointer<AsymmetricKey> in_key(_inner_key->GetPublicKey());
    QScopedPointer<AsymmetricKey> out_key(_outer_key->GetPublicKey());
    QByteArray inner_key = in_key->GetByteArray();
    QByteArray outer_key = out_key->GetByteArray();

    QByteArray msg;
    QDataStream stream(&msg, QIODevice::WriteOnly);
    stream << PublicKeys << _round_id.GetByteArray() << inner_key << outer_key;

    Broadcast(msg);
  }

  void ShuffleRound::SubmitData()
  {
    _state = DataSubmission;

    OnionEncryptor *oe = CryptoFactory::GetInstance().GetOnionEncryptor();
    oe->Encrypt(_public_inner_keys, _data, _inner_ciphertext, 0);
    oe->Encrypt(_public_outer_keys, _inner_ciphertext, _outer_ciphertext, 0);


    QByteArray msg;
    QDataStream stream(&msg, QIODevice::WriteOnly);
    stream << Data << _round_id.GetByteArray() << _outer_ciphertext;

    if(_shuffler) {
      _state = WaitingForShuffle;
    } else {
      _state = WaitingForEncryptedInnerData;
    }

    Send(msg, _shufflers.GetId(0));
  }

  void ShuffleRound::Shuffle()
  {
    _state = Shuffling;
    qDebug() << _shufflers.GetIndex(_local_id) << _group.GetIndex(_local_id)
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
      qWarning() << _shufflers.GetIndex(_local_id) << _group.GetIndex(_local_id)
        << _local_id.ToString() << ": failed to decrypt layer due to block at "
        "indexes" << bad;
      StartBlame();
      return;
    }

    oe->RandomizeBlocks(_shuffle_cleartext);

    const Id &next = _shufflers.Next(_local_id);
    MessageType mtype = (next == Id::Zero) ? EncryptedData : ShuffleData;

    QByteArray msg;
    QDataStream out_stream(&msg, QIODevice::WriteOnly);
    out_stream << mtype << _round_id.GetByteArray() << _shuffle_cleartext;

    _state = WaitingForEncryptedInnerData;

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
      qWarning() << "Did not find our message in the shuffled ciphertexts!";
    }

    MessageType mtype = found ?  GoMessage : NoGoMessage;
    QByteArray msg;
    QDataStream out_stream(&msg, QIODevice::WriteOnly);
    out_stream << mtype << _round_id.GetByteArray();

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
    }

    Broadcast(msg);
  }

  void ShuffleRound::BroadcastPrivateKey()
  {
    _state = PrivateKeySharing;

    if(!_shuffler) {
      qDebug() << _shufflers.GetIndex(_local_id) << _group.GetIndex(_local_id)
        << _local_id.ToString() << ": received sufficient go messages, "
        "waiting for keys.";
      return;
    }

    qDebug() << _shufflers.GetIndex(_local_id) << _group.GetIndex(_local_id)
      << _local_id.ToString() << ": received sufficient go messages, "
      "broadcasting private key.";

    QByteArray msg;
    QDataStream stream(&msg, QIODevice::WriteOnly);
    stream << PrivateKey << _round_id.GetByteArray() << _inner_key->GetByteArray();

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
        qWarning() << _group.GetIndex(_local_id) << _local_id.ToString() <<
          ": failed to decrypt final layers due to block at index" << bad;
        _state = Finished;
        Close("Round unsuccessfully finished.");
        return;
      }

      cleartexts = tmp;
    }

    foreach(QByteArray cleartext, cleartexts) {
      QByteArray msg = GetData(cleartext);
      if(msg.isEmpty()) {
        continue;
      }
      qDebug() << "Received a valid message: " << msg.size() << msg.toBase64();
      PushData(msg, this);
    }
    _successful = true;
    _state = Finished;

    qDebug() << _group.GetIndex(_local_id) << _local_id.ToString() <<
        ": round finished successfully";
    Close("Round successfully finished.");
  }

  void ShuffleRound::StartBlame()
  {
    if(_state == BlameInit) {
      qWarning() << "Already in blame state.";
      return;
    }

    qDebug() << _group.GetIndex(_local_id) << _local_id.ToString() <<
        ": entering blame state.";

    _blame_state = _state;
    _state = BlameInit;
    _blame_verifications = 0;

    QByteArray log = _log.Serialize();
    QByteArray msg;
    QDataStream stream(&msg, QIODevice::WriteOnly);
    stream << BlameData << _round_id.GetByteArray();

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

    sigstream << BlameData << _round_id.GetByteArray() << hashalgo->ComputeHash();
    QByteArray signature = _signing_key->Sign(sigmsg);
    stream << signature;
    
    Broadcast(msg);
  }

  void ShuffleRound::BroadcastBlameVerification()
  {
    qDebug() << _group.GetIndex(_local_id) << _local_id.ToString() <<
        ": broadcasting blame state.";
    _state = BlameShare;

    QByteArray msg;
    QDataStream stream(&msg, QIODevice::WriteOnly);
    stream << BlameVerification << _round_id.GetByteArray() <<
      _blame_hash << _blame_signatures;

    Broadcast(msg);
  }

  void ShuffleRound::BlameRound()
  {
    qDebug() << _group.GetIndex(_local_id) << _local_id.ToString() <<
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

    ShuffleBlamer sb(_group, _shufflers, GetId(), _round_id, _logs,
        _private_outer_keys);
    sb.Start();
    for(int idx = 0; idx < sb.GetBadNodes().count(); idx++) {
      if(sb.GetBadNodes()[idx]) {
        qWarning() << "Bad nodes: " << idx;
        _bad_members.append(idx);
      }
    }
    _state = Finished;
    Close("Round caused blame and finished unsuccessfully.");
  }
}
}
