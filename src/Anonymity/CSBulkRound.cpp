#include "Crypto/Hash.hpp"
#include "Identity/PublicIdentity.hpp"
#include "Utils/Random.hpp"
#include "Utils/QRunTimeError.hpp"
#include "Utils/Serialization.hpp"
#include "Utils/Timer.hpp"
#include "Utils/TimerCallback.hpp"

#include "NeffKeyShuffle.hpp"
#include "CSBulkRound.hpp"

const unsigned char bit_masks[8] = {1, 2, 4, 8, 16, 32, 64, 128};

namespace Dissent {
  using Crypto::CryptoFactory;
  using Crypto::Hash;
  using Crypto::Library;
  using Identity::PublicIdentity;
  using Utils::QRunTimeError;
  using Utils::Serialization;

namespace Anonymity {
  CSBulkRound::CSBulkRound(const Group &group, const PrivateIdentity &ident,
      const Id &round_id, QSharedPointer<Network> network,
      GetDataCallback &get_data, CreateRound create_shuffle) :
    BaseBulkRound(group, ident, round_id, network, get_data, create_shuffle),
    _state_machine(this),
    _stop_next(false)
  {
    _state_machine.AddState(OFFLINE);
    _state_machine.AddState(SHUFFLING, -1, 0, &CSBulkRound::StartShuffle);
    _state_machine.AddState(FINISHED);

    _state_machine.AddState(PREPARE_FOR_BULK, -1, 0,
        &CSBulkRound::PrepareForBulk);
    
    if(GetShuffleRound().dynamicCast<NeffKeyShuffle>()) {
      _state_machine.AddState(PROCESS_KEY_SHUFFLE, -1, 0,
          &CSBulkRound::ProcessKeyShuffle);
      _state_machine.AddTransition(SHUFFLING, PROCESS_KEY_SHUFFLE);
      _state_machine.AddTransition(PROCESS_KEY_SHUFFLE, PREPARE_FOR_BULK);
    } else {
      _state_machine.AddState(PROCESS_DATA_SHUFFLE, -1, 0,
          &CSBulkRound::ProcessDataShuffle);
      _state_machine.AddTransition(SHUFFLING, PROCESS_DATA_SHUFFLE);
      _state_machine.AddTransition(PROCESS_DATA_SHUFFLE, PREPARE_FOR_BULK);
    }

    _state_machine.AddTransition(OFFLINE, SHUFFLING);
    _state_machine.SetState(OFFLINE);

    if(group.GetSubgroup().Contains(ident.GetLocalId())) {
      InitServer();
    } else {
      InitClient();
    }

    _state->slot_open = false;
  }

  void CSBulkRound::InitServer()
  {
    _server_state = QSharedPointer<ServerState>(new ServerState());
    _state = _server_state;
    Q_ASSERT(_state);

    _state_machine.AddState(SERVER_WAIT_FOR_CLIENT_CIPHERTEXT,
        CLIENT_CIPHERTEXT, &CSBulkRound::HandleClientCiphertext,
        &CSBulkRound::SetOnlineClients);

    _state_machine.AddState(SERVER_WAIT_FOR_CLIENT_LISTS,
        SERVER_CLIENT_LIST, &CSBulkRound::HandleServerClientList,
        &CSBulkRound::SubmitClientList);

    _state_machine.AddState(SERVER_WAIT_FOR_SERVER_COMMITS,
        SERVER_COMMIT, &CSBulkRound::HandleServerCommit,
        &CSBulkRound::SubmitCommit);

    _state_machine.AddState(SERVER_WAIT_FOR_SERVER_CIPHERTEXT,
        SERVER_CIPHERTEXT, &CSBulkRound::HandleServerCiphertext,
        &CSBulkRound::SubmitServerCiphertext);

    _state_machine.AddState(SERVER_WAIT_FOR_SERVER_VALIDATION,
        SERVER_VALIDATION, &CSBulkRound::HandleServerValidation,
        &CSBulkRound::SubmitValidation);

    _state_machine.AddState(SERVER_PUSH_CLEARTEXT, -1, 0,
        &CSBulkRound::PushCleartext);

    _state_machine.AddTransition(PREPARE_FOR_BULK,
        SERVER_WAIT_FOR_CLIENT_CIPHERTEXT);
    _state_machine.AddTransition(SERVER_WAIT_FOR_CLIENT_CIPHERTEXT,
        SERVER_WAIT_FOR_CLIENT_LISTS);
    _state_machine.AddTransition(SERVER_WAIT_FOR_CLIENT_LISTS,
        SERVER_WAIT_FOR_SERVER_COMMITS);
    _state_machine.AddTransition(SERVER_WAIT_FOR_SERVER_COMMITS,
        SERVER_WAIT_FOR_SERVER_CIPHERTEXT);
    _state_machine.AddTransition(SERVER_WAIT_FOR_SERVER_CIPHERTEXT,
        SERVER_WAIT_FOR_SERVER_VALIDATION);
    _state_machine.AddTransition(SERVER_WAIT_FOR_SERVER_VALIDATION,
        SERVER_PUSH_CLEARTEXT);
    _state_machine.AddTransition(SERVER_PUSH_CLEARTEXT,
        SERVER_WAIT_FOR_CLIENT_CIPHERTEXT);

    _state_machine.SetCycleState(SERVER_PUSH_CLEARTEXT);
  }

  void CSBulkRound::InitClient()
  {
    _state = QSharedPointer<State>(new State());
    foreach(const QSharedPointer<Connection> &con,
        GetNetwork()->GetConnectionManager()->
        GetConnectionTable().GetConnections())
    {
      if(GetGroup().GetSubgroup().Contains(con->GetRemoteId())) {
        _state->my_server = con->GetRemoteId();
        break;
      }
    }

    _state_machine.AddState(CLIENT_WAIT_FOR_CLEARTEXT,
        SERVER_CLEARTEXT, &CSBulkRound::HandleServerCleartext,
        &CSBulkRound::SubmitClientCiphertext);

    _state_machine.AddTransition(PREPARE_FOR_BULK,
        CLIENT_WAIT_FOR_CLEARTEXT);
    _state_machine.AddTransition(CLIENT_WAIT_FOR_CLEARTEXT,
        CLIENT_WAIT_FOR_CLEARTEXT);

    _state_machine.SetCycleState(CLIENT_WAIT_FOR_CLEARTEXT);
  }

  CSBulkRound::~CSBulkRound()
  {
  }

  void CSBulkRound::VerifiableBroadcastToServers(const QByteArray &data)
  {
    Q_ASSERT(IsServer());
    foreach(const PublicIdentity &pi, GetGroup().GetSubgroup()) {
      VerifiableSend(pi.GetId(), data);
    }
  }

  void CSBulkRound::VerifiableBroadcastToClients(const QByteArray &data)
  {
    Q_ASSERT(IsServer());
    foreach(const QSharedPointer<Connection> &con,
        GetNetwork()->GetConnectionManager()->
        GetConnectionTable().GetConnections())
    {
      if(!GetGroup().Contains(con->GetRemoteId()) ||
          GetGroup().GetSubgroup().Contains(con->GetRemoteId()))
      {
        continue;
      }

      VerifiableSend(con->GetRemoteId(), data);
    }
  }

  void CSBulkRound::OnStart()
  {
    Round::OnStart();
    _state_machine.StateComplete();
  }

  void CSBulkRound::OnStop()
  {
    if(IsServer()) {
      _server_state->client_ciphertext_period.Stop();
    }

    _state_machine.SetState(FINISHED);
    Round::OnStop();
  }

  void CSBulkRound::HandleDisconnect(const Id &id)
  {
    if(!GetGroup().Contains(id)) {
      return;
    }

    if((_state_machine.GetState() == OFFLINE) ||
        (_state_machine.GetState() == SHUFFLING))
    {
      GetShuffleRound()->HandleDisconnect(id);
    } else if(GetGroup().GetSubgroup().Contains(id)) {
      qDebug() << "A server (" << id << ") disconnected.";
      SetInterrupted();
      Stop("A server (" + id.ToString() +") disconnected.");
    } else {
      qDebug() << "A client (" << id << ") disconnected, ignoring.";
    }
  }

  void CSBulkRound::BeforeStateTransition()
  {
    if(_server_state) {
      _server_state->client_ciphertext_period.Stop();
      _server_state->handled_servers.clear();
    }
  }

  bool CSBulkRound::CycleComplete()
  {
    if(_server_state) {
      _server_state->handled_clients.clear();
      _server_state->client_ciphertexts.clear();
      _server_state->server_ciphertexts.clear();
    }

    if(_stop_next) {
      SetInterrupted();
      Stop("Stopped for join");
      return false;
    }
    return true;
  }

  void CSBulkRound::HandleServerCleartext(const Id &from, QDataStream &stream)
  {
    if(IsServer()) {
      throw QRunTimeError("Not a client");
    } else if(_state->my_server != from) {
      throw QRunTimeError("Not a server");
    }

    QHash<int, QByteArray> signatures;
    QByteArray cleartext;
    stream >> signatures >> cleartext;

    if(cleartext.size() != _state->msg_length) {
      throw QRunTimeError("Cleartext size mismatch: " +
          QString::number(cleartext.size()) + " :: " +
          QString::number(_state->msg_length));
    }

    int server_length = GetGroup().GetSubgroup().Count();
    for(int idx = 0; idx < server_length; idx++) {
      if(!GetGroup().GetSubgroup().GetKey(idx)->Verify(cleartext,
            signatures[idx]))
      {
        Stop("Failed to verify signatures");
        return;
      }
    }

    _state->cleartext = cleartext;
    ProcessCleartext();

    _state_machine.StateComplete();
  }

  void CSBulkRound::HandleClientCiphertext(const Id &from, QDataStream &stream)
  {
    if(!IsServer()) {
      throw QRunTimeError("Not a server");
    }

    Q_ASSERT(_server_state);

    if(!_server_state->allowed_clients.contains(from)) {
      throw QRunTimeError("Not allowed to submit a ciphertext");
    } else if(_server_state->handled_clients.contains(from)) {
      throw QRunTimeError("Already have ciphertext");
    }

    QByteArray payload;
    stream >> payload;

    if(payload.size() != _server_state->msg_length) {
      throw QRunTimeError("Incorrect message length, got " +
          QString::number(payload.size()) + " expected " +
          QString::number(_server_state->msg_length));
    }

    _server_state->handled_clients.insert(from);
    _server_state->client_ciphertexts.append(payload);

    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
      ": received client ciphertext from" << GetGroup().GetIndex(from) <<
      from.ToString() << "Have" << _server_state->client_ciphertexts.count()
      << "expecting" << _server_state->allowed_clients.count();

    if(_server_state->allowed_clients.count() ==
        _server_state->client_ciphertexts.count())
    {
      _state_machine.StateComplete();
    }
  }

  void CSBulkRound::HandleServerClientList(const Id &from, QDataStream &stream)
  {
    if(!IsServer()) {
      throw QRunTimeError("Not a server");
    } else if(!GetGroup().GetSubgroup().Contains(from)) {
      throw QRunTimeError("Not a server");
    }

    Q_ASSERT(_server_state);

    if(_server_state->handled_servers.contains(from)) {
      throw QRunTimeError("Already have client list");
    }

    QSet<Id> clients;
    stream >> clients;

    // XXX Make sure there are no overlaps in their list and our list

    _server_state->handled_clients.unite(clients);
    _server_state->handled_servers.insert(from);

    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
      ": received client list from" << GetGroup().GetIndex(from) <<
      from.ToString() << "Have" << _server_state->handled_servers.count()
      << "expecting" << GetGroup().GetSubgroup().Count();

    if(_server_state->handled_servers.count() == GetGroup().GetSubgroup().Count()) {
      _state_machine.StateComplete();
    }
  }

  void CSBulkRound::HandleServerCommit(const Id &from, QDataStream &stream)
  {
    if(!IsServer()) {
      throw QRunTimeError("Not a server");
    } else if(!GetGroup().GetSubgroup().Contains(from)) {
      throw QRunTimeError("Not a server");
    }

    Q_ASSERT(_server_state);

    if(_server_state->handled_servers.contains(from)) {
      throw QRunTimeError("Already have commit");
    }

    QByteArray commit;
    stream >> commit;

    _server_state->handled_servers.insert(from);
    _server_state->server_commits[GetGroup().GetSubgroup().GetIndex(from)] = commit;

    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
      ": received commit from" << GetGroup().GetIndex(from) <<
      from.ToString() << "Have" << _server_state->handled_servers.count()
      << "expecting" << GetGroup().GetSubgroup().Count();

    if(_server_state->handled_servers.count() == GetGroup().GetSubgroup().Count()) {
      _state_machine.StateComplete();
    }
  }

  void CSBulkRound::HandleServerCiphertext(const Id &from, QDataStream &stream)
  {
    if(!IsServer()) {
      throw QRunTimeError("Not a server");
    } else if(!GetGroup().GetSubgroup().Contains(from)) {
      throw QRunTimeError("Not a server");
    }

    Q_ASSERT(_server_state);

    if(_server_state->handled_servers.contains(from)) {
      throw QRunTimeError("Already have ciphertext");
    }

    QByteArray ciphertext;
    stream >> ciphertext;

    if(ciphertext.size() != _server_state->msg_length) {
      throw QRunTimeError("Incorrect message length, got " +
          QString::number(ciphertext.size()) + " expected " +
          QString::number(_server_state->msg_length));
    }

    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QSharedPointer<Hash> hashalgo(lib->GetHashAlgorithm());
    QByteArray commit = hashalgo->ComputeHash(ciphertext);

    if(commit != _server_state->server_commits[
        GetGroup().GetSubgroup().GetIndex(from)])
    {
      throw QRunTimeError("Does not match commit.");
    }

    _server_state->handled_servers.insert(from);
    _server_state->server_ciphertexts[GetGroup().GetSubgroup().GetIndex(from)] = ciphertext;

    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
      ": received ciphertext from" << GetGroup().GetIndex(from) <<
      from.ToString() << "Have" << _server_state->handled_servers.count()
      << "expecting" << GetGroup().GetSubgroup().Count();

    if(_server_state->handled_servers.count() == GetGroup().GetSubgroup().Count()) {
      _state_machine.StateComplete();
    }
  }

  void CSBulkRound::HandleServerValidation(const Id &from, QDataStream &stream)
  {
    if(!IsServer()) {
      throw QRunTimeError("Not a server");
    } else if(!GetGroup().GetSubgroup().Contains(from)) {
      throw QRunTimeError("Not a server");
    }

    Q_ASSERT(_server_state);

    if(_server_state->handled_servers.contains(from)) {
      throw QRunTimeError("Already have signature.");
    }

    QByteArray signature;
    stream >> signature;

    if(!GetGroup().GetSubgroup().GetKey(from)->
        Verify(_state->cleartext, signature))
    {
      throw QRunTimeError("Siganture doesn't match.");
    }

    _server_state->handled_servers.insert(from);
    _server_state->signatures[GetGroup().GetSubgroup().GetIndex(from)] = signature;

    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
      ": received validation from" << GetGroup().GetIndex(from) <<
      from.ToString() << "Have" << _server_state->handled_servers.count()
      << "expecting" << GetGroup().GetSubgroup().Count();

    if(_server_state->handled_servers.count() == GetGroup().GetSubgroup().Count()) {
      _state_machine.StateComplete();
    }
  }

  void CSBulkRound::StartShuffle()
  {
    GetShuffleRound()->Start();
  }

  QPair<QByteArray, bool> CSBulkRound::GetShuffleData(int)
  {
    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QSharedPointer<AsymmetricKey> key(lib->CreatePrivateKey());
    _state->anonymous_key = key;

    QSharedPointer<AsymmetricKey> pkey =
      QSharedPointer<AsymmetricKey>(key->GetPublicKey());
    _state->shuffle_data = pkey->GetByteArray();

    return QPair<QByteArray, bool>(_state->shuffle_data, false);
  }

  void CSBulkRound::ShuffleFinished()
  {
    if(!GetShuffleRound()->Successful()) {
      SetBadMembers(GetShuffleRound()->GetBadMembers());
      if(GetShuffleRound()->Interrupted()) {
        SetInterrupted();
      }
      Stop("ShuffleRound failed");
      return;
    }

    _state_machine.StateComplete();
  }

  void CSBulkRound::ProcessDataShuffle()
  {
    if(GetShuffleSink().Count() != GetGroup().Count()) {
      qFatal("Did not receive a descriptor from everyone.");
    }

    Library *lib = CryptoFactory::GetInstance().GetLibrary();

    int count = GetShuffleSink().Count();
    for(int idx = 0; idx < count; idx++) {
      QPair<QSharedPointer<ISender>, QByteArray> pair(GetShuffleSink().At(idx));
      QSharedPointer<AsymmetricKey> key(
        lib->LoadPublicKeyFromByteArray(pair.second));

      if(!key->IsValid()) {
        qDebug() << "Invalid key in shuffle.";
        continue;
      }

      if(_state->shuffle_data == pair.second) {
        _state->my_idx = _state->anonymous_keys.count();
      }
      _state->anonymous_keys.append(key);
    }

    _state_machine.StateComplete();
  }

  void CSBulkRound::ProcessKeyShuffle()
  {
    QSharedPointer<NeffKeyShuffle> nks =
      GetShuffleRound().dynamicCast<NeffKeyShuffle>();
    Q_ASSERT(nks);

    _state->anonymous_key = nks->GetAnonymizedKey();
    Q_ASSERT(_state->anonymous_key);

    _state->my_idx = nks->GetAnonymizedKeyIndex();
    Q_ASSERT(_state->my_idx > -1);

    _state->anonymous_keys = nks->GetAnonymizedKeys();
    Q_ASSERT(_state->my_idx < _state->anonymous_keys.count());

    _state_machine.StateComplete();
  }

  void CSBulkRound::PrepareForBulk()
  {
    _state->msg_length = (GetGroup().Count() / 8);
    if(GetGroup().Count() % 8) {
      ++_state->msg_length;
    }
    _state->base_msg_length = _state->msg_length;

    SetupRngSeeds();
    _state_machine.StateComplete();
  }

  void CSBulkRound::SetupRngSeeds()
  {
    QVector<PublicIdentity> roster;
    if(IsServer()) {
      roster = GetGroup().GetRoster();
    } else {
      roster = GetGroup().GetSubgroup().GetRoster();
    }

    foreach(const PublicIdentity &gc, roster) {
      if(gc.GetId() == GetLocalId()) {
        _state->base_seeds.append(QByteArray());
        continue;
      }
      QByteArray base_seed =
        GetPrivateIdentity().GetDhKey()->GetSharedSecret(gc.GetDhKey());
      _state->base_seeds.append(base_seed);
    }
  }

  void CSBulkRound::SetupRngs()
  {
    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QSharedPointer<Hash> hashalgo(lib->GetHashAlgorithm());

    QByteArray phase(4, 0);
    Serialization::WriteInt(_state_machine.GetPhase(), phase, 0);

    _state->anonymous_rngs.clear();

    QList<QByteArray> seeds = _state->base_seeds;
    if(IsServer()) {
      seeds = QList<QByteArray>();
      foreach(const Id &id, _server_state->handled_clients) {
        int idx = GetGroup().GetIndex(id);
        seeds.append(_state->base_seeds[idx]);
      }

      for(int idx = 0; idx < GetGroup().GetSubgroup().Count(); idx++) {
        const Id &id = GetGroup().GetSubgroup().GetId(idx);
        if(id == GetLocalId()) {
          continue;
        }
        int jdx = GetGroup().GetIndex(id);
        seeds.append(_state->base_seeds[jdx]);
      }
    }

    foreach(const QByteArray &base_seed, seeds) {
      if(base_seed.isEmpty()) {
        continue;
      }
      hashalgo->Update(base_seed);
      hashalgo->Update(phase);
      hashalgo->Update(GetRoundId().GetByteArray());
      QByteArray seed = hashalgo->ComputeHash();
      QSharedPointer<Random> rng(lib->GetRandomNumberGenerator(seed));
      _state->anonymous_rngs.append(rng);
    }
  }

  void CSBulkRound::SubmitClientCiphertext()
  {
    SetupRngs();

    QByteArray payload;
    QDataStream stream(&payload, QIODevice::WriteOnly);
    stream << CLIENT_CIPHERTEXT << GetRoundId() << _state_machine.GetPhase()
      << GenerateCiphertext();

    VerifiableSend(_state->my_server, payload);
  }

  QByteArray CSBulkRound::GenerateCiphertext()
  {
    QByteArray xor_msg(_state->msg_length, 0);
    QByteArray tmsg(_state->msg_length, 0);
    
    foreach(const QSharedPointer<Random> &rng, _state->anonymous_rngs) {
      rng->GenerateBlock(tmsg);
      Xor(xor_msg, xor_msg, tmsg);
    }

    if(_state->slot_open) {
      int offset = _state->base_msg_length;
      foreach(int owner, _state->next_messages.keys()) {
        if(owner == _state->my_idx) {
          break;
        }
        offset += _state->next_messages[owner];
      }

      qDebug() << "Writing ciphertext into my slot" << _state->my_idx <<
        "starting at" << offset;
      QByteArray my_msg = GenerateSlotMessage();
      QByteArray my_xor_base = QByteArray::fromRawData(xor_msg.constData() +
          offset, my_msg.size());
      Xor(my_msg, my_msg, my_xor_base);
      xor_msg.replace(offset, my_msg.size(), my_msg);
    } else if(CheckData()) {
      qDebug() << "Opening my slot" << _state->my_idx;
      xor_msg[_state->my_idx / 8] = xor_msg[_state->my_idx / 8] ^
        bit_masks[_state->my_idx % 8];
      _state->slot_open = true;
      _state->read = false;
    }

    return xor_msg;
  }

  bool CSBulkRound::CheckData()
  {
    if(!_state->next_msg.isEmpty()) {
      return true;
    }

    QPair<QByteArray, bool> pair = GetData(4096);
    _state->next_msg = pair.first;
    return !_state->next_msg.isEmpty();
  }

  QByteArray CSBulkRound::GenerateSlotMessage()
  {
    QByteArray msg = _state->next_msg;
    if(_state->read) {
      QPair<QByteArray, bool> pair = GetData(4096);
      _state->next_msg = pair.first;
    } else {
      msg = QByteArray();
    }
    _state->read = true;

    QByteArray msg_p(8, 0);
    Serialization::WriteInt(_state_machine.GetPhase(), msg_p, 0);
    int length = _state->next_msg.size() + SlotHeaderLength(_state->my_idx);
    if(_state->next_msg.size() == 0) {
      _state->slot_open = false;
      length = 0;
    }
    Serialization::WriteInt(length, msg_p, 4);
    msg_p.append(msg);
    QByteArray sig = _state->anonymous_key->Sign(msg_p);

    QByteArray accusation(1, 0);
    if(_state->accuse) {
      accusation = QByteArray(1, 0xFF);
    }

    QByteArray msg_pp = accusation + msg_p + sig;
    return Randomize(msg_pp);
  }

  void CSBulkRound::SetOnlineClients()
  {
    _server_state->allowed_clients.clear();

    foreach(const QSharedPointer<Connection> &con,
        GetNetwork()->GetConnectionManager()->
        GetConnectionTable().GetConnections())
    {
      if(!GetGroup().Contains(con->GetRemoteId()) ||
          GetGroup().GetSubgroup().Contains(con->GetRemoteId()))
      {
        continue;
      }

      _server_state->allowed_clients.insert(con->GetRemoteId());
    }

    if(_server_state->allowed_clients.count() == 0) {
      _state_machine.StateComplete();
      return;
    }

    Utils::TimerCallback *cb = new Utils::TimerMethod<CSBulkRound, int>(
        this, &CSBulkRound::ConcludeClientCiphertextSubmission, 0);
    _server_state->client_ciphertext_period =
      Utils::Timer::GetInstance().QueueCallback(cb, CLIENT_SUBMISSION_WINDOW);
  }

  void CSBulkRound::ConcludeClientCiphertextSubmission(const int &)
  {
    qDebug() << "Client window has closed, unfortunately some client may not"
      << "have transmitted in time.";
    _state_machine.StateComplete();
  }

  void CSBulkRound::SubmitClientList()
  {
    QByteArray payload;
    QDataStream stream(&payload, QIODevice::WriteOnly);
    stream << SERVER_CLIENT_LIST << GetRoundId() <<
      _state_machine.GetPhase() << _server_state->handled_clients;

    VerifiableBroadcastToServers(payload);
  }

  void CSBulkRound::SubmitCommit()
  {
    SetupRngs();

    qDebug() << ToString() << "generating ciphertext for" <<
      _state->anonymous_rngs.count() << "out of" << GetGroup().Count();

    GenerateServerCiphertext();

    QByteArray payload;
    QDataStream stream(&payload, QIODevice::WriteOnly);
    stream << SERVER_COMMIT << GetRoundId() <<
      _state_machine.GetPhase() << _server_state->my_commit;

    VerifiableBroadcastToServers(payload);
  }

  void CSBulkRound::GenerateServerCiphertext()
  {
    QByteArray ciphertext = GenerateCiphertext();
    foreach(const QByteArray &text, _server_state->client_ciphertexts) {
      Xor(ciphertext, ciphertext, text);
    }
    _server_state->my_ciphertext = ciphertext;

    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QSharedPointer<Hash> hashalgo(lib->GetHashAlgorithm());
    _server_state->my_commit = hashalgo->ComputeHash(ciphertext);
  }

  void CSBulkRound::SubmitServerCiphertext()
  {
    QByteArray payload;
    QDataStream stream(&payload, QIODevice::WriteOnly);
    stream << SERVER_CIPHERTEXT << GetRoundId() <<
      _state_machine.GetPhase() << _server_state->my_ciphertext;

    VerifiableBroadcastToServers(payload);
  }

  void CSBulkRound::SubmitValidation()
  {
    QByteArray cleartext(_state->msg_length, 0);

    foreach(const QByteArray &ciphertext, _server_state->server_ciphertexts) {
      Xor(cleartext, cleartext, ciphertext);
    }

    _state->cleartext = cleartext;
    QByteArray signature = GetPrivateIdentity().GetSigningKey()->
      Sign(_state->cleartext);

    QByteArray payload;
    QDataStream stream(&payload, QIODevice::WriteOnly);
    stream << SERVER_VALIDATION << GetRoundId() <<
      _state_machine.GetPhase() << signature;

    VerifiableBroadcastToServers(payload);
  }

  void CSBulkRound::PushCleartext()
  {
    QByteArray payload;
    QDataStream stream(&payload, QIODevice::WriteOnly);
    stream << SERVER_CLEARTEXT << GetRoundId() << _state_machine.GetPhase()
      << _server_state->signatures << _server_state->cleartext;

    VerifiableBroadcastToClients(payload);
    ProcessCleartext();
    _state_machine.StateComplete();
  }

  void CSBulkRound::ProcessCleartext()
  {
    int next_msg_length = _state->base_msg_length;
    QMap<int, int> next_msgs;
    for(int idx = 0; idx < GetGroup().Count(); idx++) {
      if(_state->cleartext[idx / 8] & bit_masks[idx % 8]) {
        int length = SlotHeaderLength(idx);
        next_msgs[idx] = length;
        next_msg_length += length;
        qDebug() << "Opening slot" << idx;
      }
    }

    int offset = GetGroup().Count() / 8;
    if(GetGroup().Count() % 8) {
      ++offset;
    }

    foreach(int owner, _state->next_messages.keys()) {
      int msg_length = _state->next_messages[owner];

      QByteArray msg_ppp = QByteArray::fromRawData(
          _state->cleartext.constData() + offset, msg_length);
      offset += msg_length;

      QByteArray msg_pp = Derandomize(msg_ppp);

      if(msg_pp[0] != char(0)) {
        qWarning() << "Accusation generated.";
      }
      
      QSharedPointer<AsymmetricKey> vkey(_state->anonymous_keys[owner]);
      int sig_length = vkey->GetKeySize() / 8;

      QByteArray msg_p = QByteArray::fromRawData(
          msg_pp.constData() + 1, msg_pp.size() - 1 - sig_length);
      QByteArray sig = QByteArray::fromRawData(
          msg_pp.constData() + 1 + msg_p.size(), sig_length);

      int phase = Serialization::ReadInt(msg_p, 0);
      if(phase != _state_machine.GetPhase()) {
        qDebug() << "Incorret phase, skipping message";
        continue;
      }

      if(!vkey->Verify(msg_p, sig)) {
        qDebug() << "Unable to verify message for peer at" << owner;
        _state->read = (owner != _state->my_idx);
        next_msg_length += msg_length;
        next_msgs[owner] = msg_length;
        continue;
      }

      int next = Serialization::ReadInt(msg_p, 4);
      if(next < 0) {
        qDebug() << "Invalid next message size, skipping message";
        continue;
      } else if(next > 0) {
        qDebug() << "Slot" << owner << "next message length:" << next;
        next_msgs[owner] = next;
        next_msg_length += next;
      } else {
        qDebug() << "Slot" << owner << "closing";
      }

      QByteArray msg(msg_p.constData() + 8, msg_p.size() - 8);
      if(!msg.isEmpty()) {
        qDebug() << ToString() << "received a valid message.";
        PushData(GetSharedPointer(), msg);
      }
    }

    _state->next_messages = next_msgs;
    _state->msg_length = next_msg_length;
  }

  QByteArray CSBulkRound::Randomize(const QByteArray &msg)
  {
    Library *lib = CryptoFactory::GetInstance().GetLibrary();

    QSharedPointer<Random> rng0(lib->GetRandomNumberGenerator());
    QByteArray seed(lib->RngOptimalSeedSize(), 0);
    rng0->GenerateBlock(seed);

    QSharedPointer<Random> rng1(lib->GetRandomNumberGenerator(seed));
    QByteArray random_text(msg.size(), 0);
    rng1->GenerateBlock(random_text);

    Xor(random_text, random_text, msg);

    return seed + random_text;
  }

  QByteArray CSBulkRound::Derandomize(const QByteArray &randomized_text)
  {
    Library *lib = CryptoFactory::GetInstance().GetLibrary();

    QByteArray seed = QByteArray::fromRawData(randomized_text.constData(),
        lib->RngOptimalSeedSize());
    QSharedPointer<Random> rng(lib->GetRandomNumberGenerator(seed));

    QByteArray msg = QByteArray::fromRawData(
        randomized_text.constData() + seed.size(),
        randomized_text.size() - seed.size());

    QByteArray random_text(msg.size(), 0);
    rng->GenerateBlock(random_text);

    Xor(random_text, random_text, msg);
    return random_text;
  }
}
}
