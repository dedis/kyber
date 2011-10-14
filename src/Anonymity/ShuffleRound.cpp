#include "ShuffleRound.hpp"

#include "../Crypto/OnionEncryptor.hpp"


namespace Dissent {
namespace Anonymity {
  const QByteArray ShuffleRound::DefaultData = QByteArray(ShuffleRound::BlockSize + 4, 0);

  ShuffleRound::ShuffleRound(const Id &local_id, const Group &group,
      const ConnectionTable &ct, RpcHandler &rpc, const Id &session_id,
      AsymmetricKey *signing_key, const QByteArray &data) :
    Round(local_id, group, ct, rpc, session_id),
    _signing_key(signing_key),
    _state(Offline),
    _blame_state(Offline),
    _public_inner_keys(group.GetSize()),
    _public_outer_keys(group.GetSize()),
    _private_inner_keys(group.GetSize()),
    _keys_received(0),
    _inner_key(new CppPrivateKey()),
    _outer_key(new CppPrivateKey()),
    _data_received(0),
    _go(0),
    _go_received(_group.GetSize(), false)
  {
    if(data == DefaultData) {
      _data = data;
      return;
    }

    if(data.size() > BlockSize) {
      qWarning() << "Attempted to send a data larger than the block size:" <<
        data.size() << ":" << BlockSize;
      _data = DefaultData;
      return;
    }

    qDebug() << _group.GetIndex(_local_id) << _local_id.ToString() <<
      "Sending real data:" << data.size() << data.toBase64();

    _data = PrepareData(data);
  }

  QByteArray ShuffleRound::PrepareData(QByteArray data)
  {
    QByteArray msg(4, 0);

    int size = data.size();
    int idx = 0;
    while(size > 0) {
      msg[idx++] = (size & 0xFF);
      size >>= 8;
    }

    msg.append(data);
    msg.resize(BlockSize + 4);
    return msg;
  }

  QByteArray ShuffleRound::GetData(QByteArray data)
  {
    int size = 0;
    for(int idx = 0; idx < 4; idx++) {
      size |= (data[idx] << (8 * idx));
    }

    if(size == 0) {
      return QByteArray();
    }

    if(size > BlockSize || size > data.size() - 4) {
      qWarning() << "Received bad cleartext...";
      return QByteArray();
    }

    return QByteArray(data.data() + 4, size);
  }

  ShuffleRound::~ShuffleRound()
  {
    delete _inner_key;
    delete _outer_key;

    foreach(AsymmetricKey *key, _public_inner_keys) {
      if(key) {
        delete key;
      }
    }

    foreach(AsymmetricKey *key, _public_outer_keys) {
      if(key) {
        delete key;
      }
    }

    foreach(AsymmetricKey *key, _private_inner_keys) {
      if(key) {
        delete key;
      }
    }
  }

  void ShuffleRound::Broadcast(const QByteArray &data)
  {
    QByteArray msg = data + _signing_key->Sign(data);
    _out_log.Append(msg, Id::Zero);
    Round::Broadcast(msg);
  }

  void ShuffleRound::Send(const QByteArray &data, const Id &id)
  {
    QByteArray msg = data + _signing_key->Sign(data);
    _out_log.Append(msg, id);
    Round::Send(msg, id);
  }

  void ShuffleRound::Start()
  {
    if(_state != Offline) {
      qWarning() << "Called start on ShuffleRound more than once.";
      return;
    }
    if(_group.GetIndex(_local_id) == 0) {
      _shuffle_data = QVector<QByteArray>(_group.GetSize());
    }

    BroadcastPublicKeys();
  }

  void ShuffleRound::HandlePublicKeys(QDataStream &stream, const Id &id)
  {
    qDebug() << _group.GetIndex(_local_id) << _local_id.ToString() <<
        ": received public keys from " << _group.GetIndex(id) << id.ToString();

    if(_state != Offline && _state != KeySharing) {
      qWarning() << "Received a key message while in state " <<
        StateToString(_state) << " from " << id.ToString();
      return;
    }

    int idx = _group.GetIndex(id);
    int kidx = _group.GetSize() - 1 - idx;
    if(_public_inner_keys[kidx] != 0 || _public_outer_keys[kidx] != 0) {
      qWarning() << _group.GetIndex(_local_id) << _local_id.ToString() <<
          ": received duplicate public keys from " << _group.GetIndex(id)
          << id.ToString();
      return;
    }

    QByteArray inner_key, outer_key;
    stream >> inner_key >> outer_key;
    _public_inner_keys[kidx] = new CppPublicKey(inner_key);
    _public_outer_keys[kidx] = new CppPublicKey(outer_key);

    if(!_public_inner_keys[kidx]->IsValid()) {
      qWarning() << _group.GetIndex(_local_id) << _local_id.ToString() <<
        ": invalid inner key from " << idx << id.ToString();
    } else if(!_public_outer_keys[kidx]->IsValid()) {
      qWarning() << _group.GetIndex(_local_id) << _local_id.ToString() <<
        ": invalid outer key from " << idx << id.ToString();
    }

    if(++_keys_received == _group.GetSize()) {
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
      qWarning() << "Received a data message while in state " <<
        StateToString(_state) << " from " << id.ToString();
      return;
    }

    int idx = _group.GetIndex(_local_id);
    if(idx != 0) {
      qWarning() << "Received a data message while not the first node " <<
        " in the group.  Actual position: " << idx;
      return;
    }

    QByteArray data;
    stream >> data;

    idx = _group.GetIndex(id);

    if(data.isEmpty()) {
      qWarning() << _group.GetIndex(_local_id) << _local_id.ToString() <<
          ": received null data from " << idx << id.ToString();
      return;
    }

    if(!_shuffle_data[idx].isEmpty()) {
      if(_shuffle_data[idx] != data) {
        qWarning() << "Received a second data message from " << id.ToString();
      } else {
        qWarning() << "Received a duplicate data message from " << id.ToString();
      }
      return;
    }

    _shuffle_data[idx] = data;

    if(++_data_received == _group.GetSize()) {
      Shuffle();
    }
  }

  void ShuffleRound::HandleShuffle(QDataStream &stream, const Id &id)
  {
    qDebug() << _group.GetIndex(_local_id) << _local_id.ToString() <<
        ": received shuffle data from " << _group.GetIndex(id) << id.ToString();

    if(_state != WaitingForShuffle) {
      qWarning() << "Received a shuffle message while in state " << 
        StateToString(_state) << " from " << id.ToString();
      return;
    }

    if(_group.Previous(_local_id) != id) {
      qWarning() << "Received shuffle out of order from " << id.ToString();
      return;
    }

    stream >> _shuffle_data;

    Shuffle();
  }

  void ShuffleRound::HandleDataBroadcast(QDataStream &stream, const Id &id)
  {
    qDebug() << _group.GetIndex(_local_id) << _local_id.ToString() <<
        ": received data broadcast from " << _group.GetIndex(id) << id.ToString();

    if(_state != ShuffleDone) {
      return;
    }

    if(_group.GetSize() - 1 != _group.GetIndex(id)) {
      qWarning() << "Received data broadcast from wrong node.";
      return;
    }

    stream >> _encrypted_data;
    Verify();
  }
    
  void ShuffleRound::HandleVerification(bool go, const Id &id)
  {
    qDebug() << _group.GetIndex(_local_id) << _local_id.ToString() <<
        ": received" << go << " from " << _group.GetIndex(id)
        << id.ToString();

    if(_state != Verification && _state != ShuffleDone) {
      qWarning() << "Received a GoNoGo message while in state" <<
        StateToString(_state);
      return;
    }

    if(!go) {
      return;
    }

    int idx = _group.GetIndex(id);
    if(_go_received[idx]) {
      qWarning() << "Multiple \"go\"s received from " << id.ToString();
      return;
    }
    _go_received[idx] = true;

    if(++_go == _group.GetSize()) {
      BroadcastPrivateKey();
    }
  }

  void ShuffleRound::HandlePrivateKey(QDataStream &stream, const Id &id)
  {
    qDebug() << _group.GetIndex(_local_id) << _local_id.ToString() <<
        ": received private key from " << _group.GetIndex(id) << 
        id.ToString() << ", received" << _keys_received << "keys.";

    if(_state != Verification && _state != PrivateKeySharing) {
      qWarning() << "Received a private key message while in state " <<
        StateToString(_state);
      return;
    }

    QByteArray key;
    stream >> key;
    int idx = _group.GetIndex(id);
    int kidx = _group.GetSize() - 1 - idx;
    _private_inner_keys[idx] = new CppPrivateKey(key);
    if(!_private_inner_keys[idx]->VerifyKey(*_public_inner_keys[kidx])) {
      qWarning() << "Invalid inner key for " << idx << id.ToString();
      return;
    }

    if(++_keys_received == _private_inner_keys.count()) {
      Decrypt();
    }
  }

  void ShuffleRound::HandleBlameData(QDataStream &, const Id &)
  {
  }

  void ShuffleRound::ProcessData(const QByteArray &data, const Id &id)
  {
    QByteArray payload;
    if(!Verify(data, payload, id)) {
      return;
    }

    QDataStream stream(payload);
    int mtype;

    QByteArray session_id;
    stream >> mtype >> session_id;

    MessageType msg_type = (MessageType) mtype;

    Id sid(session_id);
    if(sid != GetId()) {
      qWarning() << "Invalid session, expected " << GetId().ToString()
        << ", found " << sid.ToString();
      return;
    }

    _in_log.Append(data, id);

    switch(msg_type) {
      case PublicKeys:
        HandlePublicKeys(stream, id);
        break;
      case Data:
        HandleData(stream, id);
        break;
      case ShuffleData:
        HandleShuffle(stream, id);
        break;
      case EncryptedData:
        HandleDataBroadcast(stream, id);
        break;
      case GoMessage:
        HandleVerification(true, id);
        break;
      case NoGoMessage:
        HandleVerification(false, id);
        break;
      case PrivateKey:
        HandlePrivateKey(stream, id);
        break;
      default:
        qWarning() << "Unknown message type: " << MessageTypeToString(msg_type)
          << " from " << id.ToString();
        return;
    }
  }

  bool ShuffleRound::Verify(const QByteArray &data, QByteArray &msg, const Id &id)
  {
    AsymmetricKey *key = _group.GetKey(id);
    if(!key) {
      qWarning() << "Received malsigned data block, no such peer";
      return false;
    }

    int sig_size = AsymmetricKey::KeySize / 8;
    if(data.size() < sig_size) {
      qWarning() << "Received malsigned data block, not enough data blocks." <<
        "Expected at least: " << sig_size << " got " << data.size();
      return false;
    }

    msg = QByteArray::fromRawData(data.data(), data.size() - sig_size);
    QByteArray sig = QByteArray::fromRawData(data.data() + msg.size(), sig_size);
    return key->Verify(msg, sig);
  }

  void ShuffleRound::BroadcastPublicKeys()
  {
    _state = KeySharing;
    int idx = _group.GetIndex(_local_id);
    int kidx = _group.GetSize() - 1 - idx;
    _public_inner_keys[kidx] = _inner_key->GetPublicKey();
    _public_outer_keys[kidx] = _outer_key->GetPublicKey();
    QByteArray inner_key = _public_inner_keys[kidx]->GetByteArray();
    QByteArray outer_key = _public_outer_keys[kidx]->GetByteArray();

    QByteArray msg;
    QDataStream stream(&msg, QIODevice::WriteOnly);
    stream << PublicKeys << GetId().GetByteArray() << inner_key << outer_key;

    Broadcast(msg);
    if(++_keys_received == _group.GetSize()) {
      SubmitData();
    }
  }

  void ShuffleRound::SubmitData()
  {
    _state = DataSubmission;

    OnionEncryptor::GetInstance().Encrypt(_public_inner_keys, _data,
        _inner_ciphertext, 0);
    OnionEncryptor::GetInstance().Encrypt(_public_outer_keys, _inner_ciphertext,
        _outer_ciphertext, &_intermediate);

    Id id = _group.GetId(0);
    if(id == _local_id) {
      _shuffle_data[0] = _outer_ciphertext;
      if(++_data_received == _group.GetSize()) {
        Shuffle();
      }
      return;
    }

    QByteArray msg;
    QDataStream stream(&msg, QIODevice::WriteOnly);
    stream << Data << GetId().GetByteArray() << _outer_ciphertext;
    Send(msg, id);

    _state = WaitingForShuffle;
  }

  void ShuffleRound::Shuffle()
  {
    qDebug() << _group.GetIndex(_local_id) << ": shuffling";
    _state = Shuffling;

    for(int idx = 0; idx < _shuffle_data.count(); idx++) {
      for(int jdx = 0; jdx < _shuffle_data.count(); jdx++) {
        if(idx == jdx) {
          continue;
        }
        if(_shuffle_data[idx] != _shuffle_data[jdx]) {
          continue;
        }
        qWarning() << "Found duplicate cipher texts... blaming";
        // blame ?
        return;
      }
    }

    QVector<QByteArray> out_data;
    int blame = OnionEncryptor::GetInstance().Decrypt(_outer_key, _shuffle_data, out_data);
    if (blame != -1) {
      qWarning() << _group.GetIndex(_local_id) << _local_id.ToString() <<
        ": failed to decrypt layer due to block at index" << blame;
      // blame ?
      return;
    }

    const Id &next = _group.Next(_local_id);
    MessageType mtype = (next == Id::Zero) ? EncryptedData : ShuffleData;

    QByteArray msg;
    QDataStream out_stream(&msg, QIODevice::WriteOnly);
    out_stream << mtype << GetId().GetByteArray() << out_data;

    _state = ShuffleDone;

    if(mtype == EncryptedData) {
      Broadcast(msg);
      _encrypted_data = out_data;
      Verify();
    } else {
      Send(msg, next);
    }
  }

  void ShuffleRound::Verify()
  {
    MessageType mtype = (_encrypted_data.contains(_inner_ciphertext)) ?
      GoMessage : NoGoMessage;

    QByteArray msg;
    QDataStream out_stream(&msg, QIODevice::WriteOnly);
    out_stream << mtype << GetId().GetByteArray();
    if(mtype == GoMessage) {
      _go_received[_group.GetIndex(_local_id)] = true;
      _keys_received = 0;
      _state = Verification;
    } else {
      qWarning() << "Did not find our message in the shuffled ciphertexts!";
      // blame
    }
    Broadcast(msg);

    if(mtype == GoMessage && ++_go == _group.GetSize()) {
      BroadcastPrivateKey();
    }
  }


  void ShuffleRound::BroadcastPrivateKey()
  {
    qDebug() << _group.GetIndex(_local_id) << _local_id.ToString() <<
        ": received sufficient go messages, broadcasting private key.";

    int idx = _group.GetIndex(_local_id);
    _private_inner_keys[idx] = new CppPrivateKey(_inner_key->GetByteArray());

    QByteArray msg;
    QDataStream stream(&msg, QIODevice::WriteOnly);
    stream << PrivateKey << GetId().GetByteArray() << _inner_key->GetByteArray();

    Broadcast(msg);

    if(++_keys_received == _group.GetSize()) {
      Decrypt();
    }
  }

  void ShuffleRound::Decrypt()
  {
    _state = Decryption;

    QVector<QByteArray> cleartexts = _encrypted_data;
    foreach(AsymmetricKey *key, _private_inner_keys) {
      QVector<QByteArray> tmp;
      int blame = OnionEncryptor::GetInstance().Decrypt(key, cleartexts, tmp);
      cleartexts = tmp;

      if(blame != -1) {
        qWarning() << _group.GetIndex(_local_id) << _local_id.ToString() <<
          ": failed to decrypt final layers due to block at index" << blame;
        _state = Blame;
        return;
      }
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
  }
}
}
