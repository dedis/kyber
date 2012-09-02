#include "Crypto/CppDsaPrivateKey.hpp"
#include "Crypto/CppDsaPublicKey.hpp"
#include "Utils/QRunTimeError.hpp"
#include "Utils/Timer.hpp"
#include "Utils/TimerCallback.hpp"

#include "NeffKeyShuffle.hpp"

namespace Dissent {
  using Crypto::CppDsaPrivateKey;
  using Crypto::CppDsaPublicKey;
  using Utils::QRunTimeError;

namespace Anonymity {
  NeffKeyShuffle::NeffKeyShuffle(const Group &group,
      const PrivateIdentity &ident, const Id &round_id,
      QSharedPointer<Network> network,
      GetDataCallback &get_data) :
    Round(group, ident, round_id, network, get_data),
    _state_machine(this)
  {
    _state_machine.AddState(OFFLINE);
    _state_machine.AddState(KEY_GENERATION, -1, 0, &NeffKeyShuffle::GenerateKey);
    _state_machine.AddState(KEY_SUBMISSION, -1, 0, &NeffKeyShuffle::SubmitKey);
    _state_machine.AddState(WAITING_FOR_ANONYMIZED_KEYS, ANONYMIZED_KEYS,
        &NeffKeyShuffle::HandleAnonymizedKeys);
    _state_machine.AddState(PROCESSING_ANONYMIZED_KEYS, -1, 0,
        &NeffKeyShuffle::ProcessAnonymizedKeys);
    _state_machine.AddState(FINISHED);
    _state_machine.SetState(OFFLINE);

    _state_machine.AddTransition(OFFLINE, KEY_GENERATION);
    _state_machine.AddTransition(KEY_GENERATION, KEY_SUBMISSION);
    _state_machine.AddTransition(WAITING_FOR_ANONYMIZED_KEYS,
        PROCESSING_ANONYMIZED_KEYS);

    if(group.GetSubgroup().Contains(ident.GetLocalId())) {
      InitServer();
    } else {
      InitClient();
    }
  }

  NeffKeyShuffle::~NeffKeyShuffle()
  {
  }

  void NeffKeyShuffle::InitServer()
  {
    _server_state = QSharedPointer<ServerState>(new ServerState());
    _state = _server_state;

    _state_machine.AddState(SHUFFLING, -1, 0, &NeffKeyShuffle::ShuffleKeys);

    if(GetGroup().GetSubgroup().GetIndex(GetLocalId()) == 0) {
      _state_machine.AddState(WAITING_FOR_KEYS, KEY_SUBMIT,
          &NeffKeyShuffle::HandleKeySubmission,
          &NeffKeyShuffle::PrepareForKeySubmissions);

      _state_machine.AddTransition(KEY_SUBMISSION, WAITING_FOR_KEYS);
      _state_machine.AddTransition(WAITING_FOR_KEYS, SHUFFLING);
    } else {
      _state_machine.AddState(WAITING_FOR_SHUFFLE, KEY_SHUFFLE,
          &NeffKeyShuffle::HandleShuffle);

      _state_machine.AddTransition(KEY_SUBMISSION, WAITING_FOR_SHUFFLE);
      _state_machine.AddTransition(WAITING_FOR_SHUFFLE, SHUFFLING);
    }

    _state_machine.AddTransition(SHUFFLING, WAITING_FOR_ANONYMIZED_KEYS);
  }

  void NeffKeyShuffle::InitClient()
  {
    _state = QSharedPointer<State>(new State());

    _state_machine.AddTransition(KEY_SUBMISSION,
        WAITING_FOR_ANONYMIZED_KEYS);
  }

  void NeffKeyShuffle::OnStart()
  {
    Round::OnStart();
    _state_machine.StateComplete();
  }

  void NeffKeyShuffle::OnStop()
  {
    _state_machine.SetState(FINISHED);
    Round::OnStop();
  }

  void NeffKeyShuffle::HandleDisconnect(const Id &id)
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

  void NeffKeyShuffle::HandleKeySubmission(const Id &from, QDataStream &stream)
  {
    int gidx = GetGroup().GetIndex(from);
    if(_server_state->shuffle_input[gidx] != 0) {
      throw QRunTimeError("Received multiples data messages.");
    }

    Integer key;
    stream >> key;

    if(key == 0) {
      throw QRunTimeError("Received a 0 key");
    } else if(GetModulus() <= key) {
      throw QRunTimeError("Key is not valid in this modulus");
    }
    
    _server_state->shuffle_input[gidx] = key;
    ++_server_state->keys_received;
    
    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId() <<
        ": received key from" << GetGroup().GetIndex(from) << from <<
        "Have:" << _server_state->keys_received << "expect:" << GetGroup().Count();

    if(_server_state->keys_received == GetGroup().Count()) {
      _server_state->key_receive_period.Stop();
      _state_machine.StateComplete();
    }
  }

  void NeffKeyShuffle::HandleShuffle(const Id &from, QDataStream &stream)
  {
    if(GetGroup().GetSubgroup().Previous(GetLocalId()) != from) {
      throw QRunTimeError("Received a shuffle out of order");
    }

    Integer generator_input;
    QVector<Integer> shuffle_input;

    stream >> generator_input >> shuffle_input;

    if(generator_input == 0) {
      throw QRunTimeError("Invalid generator found");
    } else if(shuffle_input.count() < GetGroup().GetSubgroup().Count()) {
      throw QRunTimeError("Missing public keys");
    }

    _server_state->generator_input = generator_input;
    _server_state->shuffle_input = shuffle_input;

    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId() <<
        ": received shuffle data from" << GetGroup().GetIndex(from) << from;

    _state_machine.StateComplete();
  }

  void NeffKeyShuffle::HandleAnonymizedKeys(const Id &from,
      QDataStream &stream)
  {
    if(GetGroup().GetSubgroup().Last() != from) {
      throw QRunTimeError("Received from wrong server");
    }

    Integer new_generator;
    QVector<Integer> new_public_elements;

    stream >> new_generator >> new_public_elements;

    if(new_generator == 0) {
      throw QRunTimeError("Invalid generator found");
    } else if(new_public_elements.count() < GetGroup().GetSubgroup().Count()) {
      throw QRunTimeError("Missing public keys");
    }

    _state->new_generator = new_generator;
    _state->new_public_elements = new_public_elements;

    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId() <<
        ": received keys from" << GetGroup().GetIndex(from) << from;
    _state_machine.StateComplete();
  }

  void NeffKeyShuffle::GenerateKey()
  {
    QSharedPointer<CppDsaPrivateKey> base_key(
        CppDsaPrivateKey::GenerateKey(GetRoundId().GetByteArray()));

    _state->input_private_key = QSharedPointer<CppDsaPrivateKey>(
        new CppDsaPrivateKey(base_key->GetModulus(), base_key->GetSubgroup(),
          base_key->GetGenerator()));
    _state_machine.StateComplete();
  }

  void NeffKeyShuffle::SubmitKey()
  {
    QByteArray msg;
    QDataStream stream(&msg, QIODevice::WriteOnly);

    QSharedPointer<CppDsaPrivateKey> key(
        _state->input_private_key.dynamicCast<CppDsaPrivateKey>());
    Q_ASSERT(key);
    stream << KEY_SUBMIT << GetRoundId() << key->GetPublicElement();

    VerifiableSend(GetGroup().GetSubgroup().GetId(0), msg);
    _state_machine.StateComplete();
  }

  void NeffKeyShuffle::PrepareForKeySubmissions()
  {
    _server_state->shuffle_input = QVector<Integer>(GetGroup().Count(), 0);
    _server_state->generator_input = GetGenerator();

    Utils::TimerCallback *cb = new Utils::TimerMethod<NeffKeyShuffle, int>(
        this, &NeffKeyShuffle::ConcludeKeySubmission, 0);
    _server_state->key_receive_period =
      Utils::Timer::GetInstance().QueueCallback(cb, KEY_SUBMISSION_WINDOW);
  }

  void NeffKeyShuffle::ShuffleKeys()
  {
    _state->blame = !CheckShuffleOrder(_server_state->shuffle_input);

    QSharedPointer<CppDsaPrivateKey> tmp_key(
        new CppDsaPrivateKey(GetModulus(), GetSubgroup(), GetGenerator()));
    _server_state->exponent = tmp_key->GetPrivateExponent();
    _server_state->generator_output = _server_state->generator_input.Pow(
        _server_state->exponent, GetModulus());

    foreach(const Integer &key, _server_state->shuffle_input) {
      _server_state->shuffle_output.append(
          key.Pow(_server_state->exponent, GetModulus()));
    }

    qSort(_server_state->shuffle_output);

    const Id &next = GetGroup().GetSubgroup().Next(GetLocalId());
    MessageType mtype = (next == Id::Zero()) ? ANONYMIZED_KEYS : KEY_SHUFFLE; 

    QByteArray msg;
    QDataStream out_stream(&msg, QIODevice::WriteOnly);
    out_stream << mtype << GetRoundId() << _server_state->generator_output <<
      _server_state->shuffle_output;

    if(mtype == ANONYMIZED_KEYS) {
      VerifiableBroadcast(msg);
    } else {
      VerifiableSend(next, msg);
    }

    _state_machine.StateComplete();
  }

  void NeffKeyShuffle::ProcessAnonymizedKeys()
  {
    _state->blame = !CheckShuffleOrder(_state->new_public_elements);
    if(_state->blame) {
      return;
    }

    Integer my_element = _state->new_generator.Pow(GetPrivateExponent(),
        GetModulus());

    for(int idx = 0; idx < _state->new_public_elements.count(); idx++) {
      if(_state->new_public_elements[idx] == my_element) {
        _state->user_key_index = idx;
        _state->output_private_key = QSharedPointer<AsymmetricKey>(
            new CppDsaPrivateKey(GetModulus(), GetSubgroup(),
              _state->new_generator, GetPrivateExponent()));
        qDebug() << "Found my key at" << idx;
      }

      _state->output_keys.append(QSharedPointer<AsymmetricKey>(
            new CppDsaPublicKey(GetModulus(), GetSubgroup(),
              _state->new_generator, _state->new_public_elements[idx]))); 
    }

    if(_state->user_key_index == -1) {
      _state->blame = true;
      qDebug() << "Did not find my key";
    } else {
      SetSuccessful(true);
    }
    Stop("Round finished");
  }

  bool NeffKeyShuffle::CheckShuffleOrder(const QVector<Crypto::Integer> &keys)
  {
    Integer pkey(0);
    foreach(const Integer &key, keys) {
      if(key <= pkey) {
        qDebug() << "Duplicate keys or unordered, blaming.";
        return false;
      }
    }
    return true;
  }

  void NeffKeyShuffle::ConcludeKeySubmission(const int &)
  {
    qDebug() << "Key window has closed, unfortunately some keys may not"
      << "have transmitted in time.";

    QVector<Integer> pruned_keys;
    foreach(const Integer &key, _server_state->shuffle_input) {
      if(key != 0) {
        pruned_keys.append(key);
      }
    }

    _server_state->shuffle_input = pruned_keys;

    _state_machine.StateComplete();
  }
}
}

