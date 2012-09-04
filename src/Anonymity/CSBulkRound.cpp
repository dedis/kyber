/**
 * Handle false accusations
 * Implement misbehaving servers
 * Implement colluding server
 * Eventually handle "light weight" consensus amongst all non-colluding servers when a server equivocates
 * Consider how to have server exchange ciphertext bits ... already know both colluding parties one needs to submit the shared secret
 */

#include "Crypto/Hash.hpp"
#include "Identity/PublicIdentity.hpp"
#include "Utils/Random.hpp"
#include "Utils/QRunTimeError.hpp"
#include "Utils/Serialization.hpp"
#include "Utils/Time.hpp"
#include "Utils/Timer.hpp"
#include "Utils/TimerCallback.hpp"
#include "Utils/Utils.hpp"

#include "NeffKeyShuffle.hpp"
#include "NeffShuffle.hpp"
#include "NullRound.hpp"
#include "CSBulkRound.hpp"

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
    _stop_next(false),
    _get_blame_data(this, &CSBulkRound::GetBlameData)
  {
    _state_machine.AddState(OFFLINE);
    _state_machine.AddState(SHUFFLING, -1, 0, &CSBulkRound::StartShuffle);
    _state_machine.AddState(PREPARE_FOR_BULK, -1, 0,
        &CSBulkRound::PrepareForBulk);
    _state_machine.AddState(STARTING_BLAME_SHUFFLE, -1, 0,
        &CSBulkRound::StartBlameShuffle);
    _state_machine.AddState(WAITING_FOR_BLAME_SHUFFLE, -1, 0,
        &CSBulkRound::ProcessBlameShuffle);
    _state_machine.AddState(FINISHED);

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
    _state_machine.AddTransition(STARTING_BLAME_SHUFFLE,
        WAITING_FOR_BLAME_SHUFFLE);
    _state_machine.SetState(OFFLINE);

    if(group.GetSubgroup().Contains(ident.GetLocalId())) {
      InitServer();
    } else {
      InitClient();
    }

    _state->slot_open = false;

    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QScopedPointer<Hash> hashalgo(lib->GetHashAlgorithm());
    QByteArray hashval = GetRoundId().GetByteArray();
    hashval = hashalgo->ComputeHash(hashval);
    hashval = hashalgo->ComputeHash(hashval);
    Id bsr_id(hashval);

    QSharedPointer<Network> net(GetNetwork()->Clone());
    QVariantHash headers = net->GetHeaders();
    headers["bulk"] = false;
    headers["special"] = true;
    net->SetHeaders(headers);
#if DISSENT_TEST
    _state->blame_shuffle = QSharedPointer<Round>(new NullRound(GetGroup(),
          GetPrivateIdentity(), bsr_id, net, _get_blame_data));
#else
    _state->blame_shuffle = QSharedPointer<Round>(new NeffShuffle(GetGroup(),
          GetPrivateIdentity(), bsr_id, net, _get_blame_data));
#endif
    QObject::connect(_state->blame_shuffle.data(), SIGNAL(Finished()),
        this, SLOT(OperationFinished()));
    _state->blame_shuffle->SetSink(&_blame_sink);
  }

  void CSBulkRound::InitServer()
  {
    _server_state = QSharedPointer<ServerState>(new ServerState());
    _state = _server_state;
    Q_ASSERT(_state);

    _server_state->current_phase_log =
      QSharedPointer<PhaseLog>(
          new PhaseLog(_state_machine.GetPhase(), GetGroup().Count()));
    _server_state->phase_logs[_state_machine.GetPhase()] =
      _server_state->current_phase_log;

#ifndef CSBR_RECONNECTS
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
#endif
    _server_state->handled_clients.fill(false, GetGroup().Count());

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
    _state_machine.AddState(SERVER_TRANSMIT_BLAME_BITS, -1, 0,
        &CSBulkRound::TransmitBlameBits);
    _state_machine.AddState(SERVER_WAITING_FOR_BLAME_BITS, SERVER_BLAME_BITS,
        &CSBulkRound::HandleBlameBits);
    _state_machine.AddState(SERVER_REQUEST_CLIENT_REBUTTAL, -1, 0,
        &CSBulkRound::RequestRebuttal);
    _state_machine.AddState(SERVER_WAIT_FOR_CLIENT_REBUTTAL, CLIENT_REBUTTAL,
        &CSBulkRound::HandleRebuttal);
    _state_machine.AddState(SERVER_EXCHANGE_VERDICT_SIGNATURE, -1, 0,
        &CSBulkRound::SubmitVerdictSignature);
    _state_machine.AddState(SERVER_SHARE_VERDICT, -1, 0,
        &CSBulkRound::PushVerdict);
    _state_machine.AddState(SERVER_WAIT_FOR_VERDICT_SIGNATURE,
        SERVER_VERDICT_SIGNATURE, &CSBulkRound::HandleVerdictSignature);

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

    _state_machine.AddTransition(WAITING_FOR_BLAME_SHUFFLE,
        SERVER_TRANSMIT_BLAME_BITS);
    _state_machine.AddTransition(SERVER_TRANSMIT_BLAME_BITS,
        SERVER_WAITING_FOR_BLAME_BITS);
    _state_machine.AddTransition(SERVER_WAITING_FOR_BLAME_BITS,
        SERVER_REQUEST_CLIENT_REBUTTAL);
    _state_machine.AddTransition(SERVER_REQUEST_CLIENT_REBUTTAL,
        SERVER_WAIT_FOR_CLIENT_REBUTTAL);
    _state_machine.AddTransition(SERVER_WAIT_FOR_CLIENT_REBUTTAL,
        SERVER_EXCHANGE_VERDICT_SIGNATURE);
    _state_machine.AddTransition(SERVER_EXCHANGE_VERDICT_SIGNATURE,
        SERVER_WAIT_FOR_VERDICT_SIGNATURE);
    _state_machine.AddTransition(SERVER_WAIT_FOR_VERDICT_SIGNATURE,
        SERVER_SHARE_VERDICT);
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
    _state_machine.AddState(WAITING_FOR_DATA_REQUEST_OR_VERDICT,
        SERVER_REBUTTAL_OR_VERDICT, &CSBulkRound::HandleRebuttalOrVerdict);

    _state_machine.AddTransition(PREPARE_FOR_BULK,
        CLIENT_WAIT_FOR_CLEARTEXT);
    _state_machine.AddTransition(CLIENT_WAIT_FOR_CLEARTEXT,
        CLIENT_WAIT_FOR_CLEARTEXT);

    _state_machine.SetCycleState(CLIENT_WAIT_FOR_CLEARTEXT);

    _state_machine.AddTransition(WAITING_FOR_BLAME_SHUFFLE,
        WAITING_FOR_DATA_REQUEST_OR_VERDICT);
  }

  CSBulkRound::~CSBulkRound()
  {
  }

  void CSBulkRound::VerifiableBroadcastToServers(const QByteArray &data)
  {
    Q_ASSERT(IsServer());

    QByteArray msg = data + GetSigningKey()->Sign(data);
    foreach(const PublicIdentity &pi, GetGroup().GetSubgroup()) {
      GetNetwork()->Send(pi.GetId(), msg);
    }
  }

  void CSBulkRound::VerifiableBroadcastToClients(const QByteArray &data)
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
    Utils::PrintResourceUsage(ToString() + " " + "finished bulk");
    Round::OnStop();
  }

  void CSBulkRound::HandleDisconnect(const Id &id)
  {
    if(!GetGroup().Contains(id)) {
      return;
    }

#ifndef CSBR_RECONNECTS
    if(IsServer() && GetGroup().Contains(id)) {
      _server_state->allowed_clients.remove(id);
    }
#endif

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
      _server_state->handled_clients.fill(false, GetGroup().Count());
      _server_state->client_ciphertexts.clear();
      _server_state->server_ciphertexts.clear();

      int nphase = _state_machine.GetPhase() + 1;
      if(nphase > 5) {
        _server_state->phase_logs.remove(nphase - 5);
      }
      _server_state->current_phase_log =
        QSharedPointer<PhaseLog>(
            new PhaseLog(nphase, GetGroup().Count()));
      _server_state->phase_logs[nphase] = _server_state->current_phase_log;
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

    if(_state->start_accuse) {
      _state_machine.SetState(STARTING_BLAME_SHUFFLE);
    } else {
      _state_machine.StateComplete();
    }
  }

  void CSBulkRound::HandleClientCiphertext(const Id &from, QDataStream &stream)
  {
    if(!IsServer()) {
      throw QRunTimeError("Not a server");
    }

    Q_ASSERT(_server_state);
    int idx = GetGroup().GetIndex(from);

    if(!_server_state->allowed_clients.contains(from)) {
      throw QRunTimeError("Not allowed to submit a ciphertext");
    } else if(_server_state->handled_clients.at(idx)) {
      throw QRunTimeError("Already have ciphertext");
    }

    QByteArray payload;
    stream >> payload;

    if(payload.size() != _server_state->msg_length) {
      throw QRunTimeError("Incorrect message length, got " +
          QString::number(payload.size()) + " expected " +
          QString::number(_server_state->msg_length));
    }

    _server_state->handled_clients[idx] = true;
    _server_state->client_ciphertexts.append(payload);
    _server_state->current_phase_log->messages[idx] = payload;

    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
      ": received client ciphertext from" << GetGroup().GetIndex(from) <<
      from.ToString() << "Have" << _server_state->client_ciphertexts.count()
      << "expecting" << _server_state->allowed_clients.count();

    if(_server_state->allowed_clients.count() ==
        _server_state->client_ciphertexts.count())
    {
      _state_machine.StateComplete();
    } else if(_server_state->client_ciphertexts.count() ==
        _server_state->expected_clients)
    {
      // Start the flexible deadline
      _server_state->client_ciphertext_period.Stop();
      int window = Utils::Time::GetInstance().MSecsSinceEpoch() -
        _server_state->start_of_phase;
      Utils::TimerCallback *cb = new Utils::TimerMethod<CSBulkRound, int>(
          this, &CSBulkRound::ConcludeClientCiphertextSubmission, 0);
      _server_state->client_ciphertext_period =
        Utils::Timer::GetInstance().QueueCallback(cb, window);

      qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
        "setting client submission flex-deadline:" << window;
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

    QBitArray clients;
    stream >> clients;

    /// XXX Handle overlaps in list

    _server_state->handled_clients |= clients;
    _server_state->handled_servers.insert(from);

    int sidx = GetGroup().GetSubgroup().GetIndex(from);
    for(int idx = 0; idx < clients.size(); idx++) {
      if(clients.at(0)) {
        _server_state->current_phase_log->client_to_server[idx] = sidx;
      }
    }

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
      throw QRunTimeError("Signature doesn't match.");
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

  void CSBulkRound::HandleBlameBits(const Id &from, QDataStream &stream)
  {
    if(!IsServer()) {
      throw QRunTimeError("Not a server");
    } else if(!GetGroup().GetSubgroup().Contains(from)) {
      throw QRunTimeError("Not a server");
    }

    Q_ASSERT(_server_state);

    if(_server_state->blame_bits.contains(from)) {
      throw QRunTimeError("Already have blame bits.");
    }

    QPair<QBitArray, QBitArray> blame_bits;
    stream >> blame_bits;

    /// XXX make sure the blame bits match what was sent
    /// XXX make sure servers transmit a bit for each client

    _server_state->blame_bits[from] = blame_bits;

    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
      ": received blame bits from" << GetGroup().GetIndex(from) <<
      from.ToString() << "Have" << _server_state->blame_bits.count()
      << "expecting" << GetGroup().GetSubgroup().Count();

    if(_server_state->blame_bits.count() == GetGroup().GetSubgroup().Count()) {
      _state_machine.StateComplete();
    }
  }

  void CSBulkRound::HandleRebuttal(const Id &from, QDataStream &stream)
  {
    if(from != _server_state->expected_rebuttal) {
      throw QRunTimeError("Not expecting rebuttal from client");
    }

    QPair<int, QByteArray> rebuttal;
    stream >> rebuttal;
    Id server = GetGroup().GetSubgroup().GetId(rebuttal.first);
    if(server == Id::Zero()) {
      throw QRunTimeError("Invalid server selected");
    }

    QByteArray shared_secret = GetPrivateIdentity().GetDhKey()->VerifySharedSecret(
        GetGroup().GetIdentity(from).GetDhKey(),
        GetGroup().GetIdentity(server).GetDhKey(),
        rebuttal.second);

    if(shared_secret.isEmpty()) {
      throw QRunTimeError("Invalid shared secret");
    } else if(rebuttal.first >= _server_state->server_bits.size()) {
      throw QRunTimeError("Invalid server claim");
    }

    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QSharedPointer<Hash> hashalgo(lib->GetHashAlgorithm());
    hashalgo->Update(shared_secret);

    QByteArray bphase(4, 0);
    Serialization::WriteInt(_server_state->current_blame.third, bphase, 0);
    hashalgo->Update(bphase);

    hashalgo->Update(GetRoundId().GetByteArray());
    QByteArray seed = hashalgo->ComputeHash();
    QSharedPointer<Random> rng(lib->GetRandomNumberGenerator(seed));
    int byte_idx = _server_state->current_blame.second / 8;
    int bit_idx = _server_state->current_blame.second % 8;
    QByteArray tmp(byte_idx + 1, 0);
    rng->GenerateBlock(tmp);
    if(((tmp[byte_idx] & bit_masks[bit_idx % 8]) != 0) == _server_state->server_bits[rebuttal.first]) {
      _server_state->bad_dude = from;
      qDebug() << "Client misbehaves!";
    } else {
      _server_state->bad_dude = server;
      qDebug() << "Server misbehaves!";
    }
    _state_machine.StateComplete();
  }

  void CSBulkRound::HandleVerdictSignature(const Id &from, QDataStream &stream)
  {
    if(!IsServer()) {
      throw QRunTimeError("Not a server");
    } else if(!GetGroup().GetSubgroup().Contains(from)) {
      throw QRunTimeError("Not a server");
    }

    if(_server_state->verdict_signatures.contains(from)) {
      throw QRunTimeError("Already have signature.");
    }

    QByteArray signature;
    stream >> signature;

    if(!GetGroup().GetIdentity(from).GetVerificationKey()->
        Verify(_server_state->verdict_hash, signature))
    {
      throw QRunTimeError("Signature doesn't match.");
    }

    _server_state->verdict_signatures[from] = signature;

    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
      ": received verdict signature from" << GetGroup().GetIndex(from) <<
      from.ToString() << "Have" << _server_state->verdict_signatures.count()
      << "expecting" << GetGroup().GetSubgroup().Count();

    if(_server_state->verdict_signatures.count() == GetGroup().GetSubgroup().Count()) {
      _state_machine.StateComplete();
    }
  }

  void CSBulkRound::HandleRebuttalOrVerdict(const Id &from, QDataStream &stream)
  {
    if(IsServer()) {
      throw QRunTimeError("Not a client");
    } else if(!GetGroup().GetSubgroup().Contains(from)) {
      throw QRunTimeError("Not a server");
    }

    bool verdict;
    stream >> verdict;
    if(!verdict) {
      int phase, accuse_idx;
      QBitArray server_bits;
      stream >> phase >> accuse_idx >> server_bits;

      QByteArray output;
      QDataStream ostream(&output, QIODevice::WriteOnly);
      ostream << CLIENT_REBUTTAL << GetRoundId() << _state_machine.GetPhase() <<
        GetRebuttal(phase, accuse_idx, server_bits);
      VerifiableSend(from, output);
      return;
    }

    Utils::Triple<int, int, int> blame;
    Id bad_dude;
    QVector<QByteArray> signatures;
    stream >> blame >> bad_dude >> signatures;

    QByteArray verdict_msg;
    QDataStream vstream(&verdict_msg, QIODevice::WriteOnly);
    vstream << blame << bad_dude;

    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QSharedPointer<Hash> hash(lib->GetHashAlgorithm());
    QByteArray verdict_hash = hash->ComputeHash(verdict_msg);

    int idx = 0;
    foreach(const PublicIdentity &pid, GetGroup().GetSubgroup()) {
      if(!pid.GetVerificationKey()->Verify(verdict_hash, signatures[idx++])) {
        throw QRunTimeError("Invalid verdict signature");
      }
    }

    qDebug() << "Client done, bad guy:" << bad_dude;
    SetSuccessful(false);
    if(GetGroup().Contains(bad_dude)) {
      QVector<int> bad_members;
      bad_members.append(GetGroup().GetIndex(bad_dude));
      SetBadMembers(bad_members);
      Stop("Bad member found and reported");
    } else {
      Stop("Bad member found, but I am a lowly client without knowledge of the peer");
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

  QPair<QByteArray, bool> CSBulkRound::GetBlameData(int)
  {
    if(!_state->my_accuse) {
      return QPair<QByteArray, bool>(QByteArray(), false);
    }

    QByteArray msg(12, 0);
    Serialization::WriteUInt(_state->my_idx, msg, 0);
    Serialization::WriteUInt(_state->accuse_idx, msg, 4);
    Serialization::WriteUInt(_state->blame_phase, msg, 8);
    QByteArray signature = _state->anonymous_key->Sign(msg);
    msg.append(signature);

    return QPair<QByteArray, bool>(msg, false);
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
      qFatal("Did not receive a descriptor from everyone, expected: %d, found %d.",
          GetGroup().Count(), GetShuffleSink().Count());
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

    _state->anonymous_key = nks->GetKey();
    Q_ASSERT(_state->anonymous_key);

    _state->my_idx = nks->GetKeyIndex();
    Q_ASSERT(_state->my_idx > -1);

    _state->anonymous_keys = nks->GetKeys();
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
    Utils::PrintResourceUsage(ToString() + " " + "beginning bulk");
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
      _server_state->rng_to_gidx.clear();
      for(int idx = 0; idx < _server_state->handled_clients.size(); idx++) {
        if(_server_state->handled_clients.at(idx)) {
          _server_state->rng_to_gidx[seeds.size()] = idx;
          seeds.append(_state->base_seeds[idx]);
        }
      }

      /*
       * For now do not add server secrets ... makes life easier...
       * for accusations
      for(int idx = 0; idx < GetGroup().GetSubgroup().Count(); idx++) {
        const Id &id = GetGroup().GetSubgroup().GetId(idx);
        if(id == GetLocalId()) {
          continue;
        }
        int jdx = GetGroup().GetIndex(id);
        _server_state->rng_to_gidx[seeds.size()] = jdx;
        seeds.append(_state->base_seeds[jdx]);
      }
      */
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
    
    int idx = 0;
    foreach(const QSharedPointer<Random> &rng, _state->anonymous_rngs) {
      rng->GenerateBlock(tmsg);
      if(IsServer()) {
        int gidx = _server_state->rng_to_gidx[idx++];
        qDebug() << gidx << tmsg.toBase64();
        _server_state->current_phase_log->my_sub_ciphertexts[gidx] = tmsg;
      }
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

      QByteArray my_msg = GenerateSlotMessage();
      QByteArray my_xor_base = QByteArray::fromRawData(xor_msg.constData() +
          offset, my_msg.size());
      Xor(my_msg, my_msg, my_xor_base);
      xor_msg.replace(offset, my_msg.size(), my_msg);

      qDebug() << "Writing ciphertext into my slot" << _state->my_idx <<
        "starting at" << offset << "for" << my_msg.size() << "bytes.";

    } else if(CheckData()) {
      qDebug() << "Opening my slot" << _state->my_idx;
      xor_msg[_state->my_idx / 8] = xor_msg[_state->my_idx / 8] ^
        bit_masks[_state->my_idx % 8];
      _state->read = false;
      _state->slot_open = true;
    }

    return xor_msg;
  }

  bool CSBulkRound::CheckData()
  {
    if(!_state->next_msg.isEmpty()) {
      return true;
    }

    QPair<QByteArray, bool> pair = GetData(MAX_GET);
    if(pair.first.size() > 0) {
      qDebug() << "Found a message of" << pair.first.size();
    }
    _state->next_msg = pair.first;
    _state->last_msg = QByteArray();
    return !_state->next_msg.isEmpty();
  }

  QByteArray CSBulkRound::GenerateSlotMessage()
  {
    QByteArray msg = _state->next_msg;
    if(_state->read) {
      QPair<QByteArray, bool> pair = GetData(MAX_GET);
      _state->last_msg = _state->next_msg;
      _state->next_msg = pair.first;
    } else {
      msg = _state->last_msg;
      _state->read = true;
    }

    QByteArray msg_p(8, 0);
    Serialization::WriteInt(_state_machine.GetPhase(), msg_p, 0);
    int length = _state->next_msg.size() + SlotHeaderLength(_state->my_idx);
#ifdef CSBR_CLOSE_SLOT
    if(_state->next_msg.size() == 0) {
      _state->slot_open = false;
      length = 0;
    }
#endif
    if(_state->accuse) {
      Serialization::WriteInt(SlotHeaderLength(_state->my_idx), msg_p, 4);
      msg_p.append(QByteArray(msg.size(), 0));
    } else {
      Serialization::WriteInt(length, msg_p, 4);
      msg_p.append(msg);
    }
#ifdef CSBR_SIGN_SLOTS
    QByteArray sig = _state->anonymous_key->Sign(msg_p);
#else
    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QSharedPointer<Hash> hash(lib->GetHashAlgorithm());
    QByteArray sig = hash->ComputeHash(msg_p);
#endif

    QByteArray accusation(1, 0);
    if(_state->accuse) {
      accusation = QByteArray(1, 0xFF);
    }

    QByteArray msg_pp = accusation + msg_p + sig;
    _state->last_ciphertext  = Randomize(msg_pp);
    return _state->last_ciphertext;
  }

  void CSBulkRound::SetOnlineClients()
  {
#ifdef CSBR_RECONNECTS
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
#endif

    if(_server_state->allowed_clients.count() == 0) {
      _state_machine.StateComplete();
      return;
    }

    // This is the hard deadline
    Utils::TimerCallback *cb = new Utils::TimerMethod<CSBulkRound, int>(
        this, &CSBulkRound::ConcludeClientCiphertextSubmission, 0);
    _server_state->client_ciphertext_period =
      Utils::Timer::GetInstance().QueueCallback(cb, CLIENT_SUBMISSION_WINDOW);

    // Setup the flex-deadline
    _server_state->start_of_phase =
      Utils::Time::GetInstance().MSecsSinceEpoch();
    _server_state->expected_clients =
      int(_server_state->allowed_clients.count() * CLIENT_PERCENTAGE);
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
    if(_state->start_accuse) {
      _state_machine.SetState(STARTING_BLAME_SHUFFLE);
    } else {
      _state_machine.StateComplete();
    }
  }

  void CSBulkRound::StartBlameShuffle()
  {
    _state->blame_shuffle->Start();
  }

  void CSBulkRound::ProcessBlameShuffle()
  {
    if(!IsServer()) {
      _state_machine.StateComplete();
      return;
    }

    for(int idx = 0; idx < _blame_sink.Count(); idx++) {
      const QByteArray &blame = _blame_sink.At(idx).second;
      if(blame.size() <= 8) {
        qDebug() << "Found invalid blame material";
        continue;
      }

      QByteArray msg = blame.left(12);
      QByteArray signature = blame.mid(12);
      int owner_idx = Serialization::ReadInt(msg, 0);
      int accuse_idx = Serialization::ReadInt(msg, 4);
      int accuse_bidx = (accuse_idx / 8) + (accuse_idx % 8 ? 1 : 0);
      int phase = Serialization::ReadInt(msg, 8);
      if(!_server_state->phase_logs.contains(phase)) {
        qDebug() << "Phase too old" << phase;
        continue;
      }

      if(owner_idx < 0 || owner_idx >= _state->anonymous_keys.size()) {
        qDebug() << "Invalid idx claimed";
        continue;
      }

      QSharedPointer<PhaseLog> phase_log = _server_state->phase_logs[phase];
      int start = phase_log->message_offsets[owner_idx];
      int end = (owner_idx + 1 == phase_log->message_offsets.size()) ?
        phase_log->message_offsets[owner_idx + 1] :
        phase_log->message_length;

      if((end - start + accuse_bidx) <= 0) {
        qDebug() << "Invalid offset claimed";
        continue;
      }
      
      if(!_state->anonymous_keys[owner_idx]->Verify(msg, signature)) {
        qDebug() << "Invalid accusation";
        continue;
      }

      qDebug() << "Found a valid accusation for" << owner_idx << accuse_idx << phase;
      if(!_server_state->accuse_found) {
        _server_state->current_blame =
          Utils::Triple<int, int, int>(owner_idx, accuse_idx, phase);
        _server_state->accuse_found = true;
      }
    }

    if(_server_state->accuse_found) {
      _state_machine.StateComplete();
    } else {
      throw QRunTimeError("False accusation");
    }
  }

  void CSBulkRound::TransmitBlameBits()
  {
    QPair<QBitArray, QBitArray> bits =
      _server_state->phase_logs[_server_state->current_blame.third]->
      GetBitsAtIndex(_server_state->current_blame.second);

    QByteArray payload;
    QDataStream stream(&payload, QIODevice::WriteOnly);
    stream << SERVER_BLAME_BITS << GetRoundId() <<
      _state_machine.GetPhase() << bits;
    VerifiableBroadcastToServers(payload);
    _state_machine.StateComplete();
  }

  void CSBulkRound::RequestRebuttal()
  {
    QPair<int, QBitArray> pair = FindMismatch();
    int gidx = pair.first;
    if(gidx == -1) {
      qDebug() << "Did not find a mismatch";
      return;
    }

    QBitArray server_bits = pair.second;
    Id id = GetGroup().GetId(gidx);
    _server_state->expected_rebuttal = id;
    _server_state->server_bits = server_bits;

    QByteArray payload;
    QDataStream stream(&payload, QIODevice::WriteOnly);
    int accuse_idx = _server_state->current_blame.second;
    int phase = _server_state->current_blame.third;
    stream << SERVER_REBUTTAL_OR_VERDICT << GetRoundId() <<
      _state_machine.GetPhase() << false <<
      phase << accuse_idx << server_bits;
    VerifiableSend(id, payload);
    _state_machine.StateComplete();
  }

  void CSBulkRound::SubmitVerdictSignature()
  {
    QByteArray verdict;
    QDataStream vstream(&verdict, QIODevice::WriteOnly);
    vstream << _server_state->current_blame << _server_state->bad_dude;

    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QSharedPointer<Hash> hash(lib->GetHashAlgorithm());
    _server_state->verdict_hash = hash->ComputeHash(verdict);

    QByteArray signature = GetPrivateIdentity().
      GetSigningKey()->Sign(_server_state->verdict_hash);

    QByteArray payload;
    QDataStream stream(&payload, QIODevice::WriteOnly);
    stream << SERVER_VERDICT_SIGNATURE << GetRoundId() <<
      _state_machine.GetPhase() << signature;
    VerifiableBroadcastToServers(payload);
    _state_machine.StateComplete();
  }

  void CSBulkRound::PushVerdict()
  {
    QVector<QByteArray> signatures;
    foreach(const PublicIdentity &pid, GetGroup().GetSubgroup()) {
      signatures.append(_server_state->verdict_signatures[pid.GetId()]);
    }

    QByteArray payload;
    QDataStream stream(&payload, QIODevice::WriteOnly);
    stream << SERVER_REBUTTAL_OR_VERDICT << GetRoundId() <<
      _state_machine.GetPhase() << true <<
      _server_state->current_blame <<
      _server_state->bad_dude << signatures;
    VerifiableBroadcastToClients(payload);

    SetSuccessful(false);
    QVector<int> bad_members;
    bad_members.append(GetGroup().GetIndex(_server_state->bad_dude));
    SetBadMembers(bad_members);
    Stop("Bad member found and reported");
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

#ifndef CSBR_SIGN_SLOTS
    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QSharedPointer<Hash> hash(lib->GetHashAlgorithm());
    int sig_length = hash->GetDigestSize();
#endif

    if(IsServer()) {
      int calc = offset;
      for(int idx = 0; idx < GetGroup().Count(); idx++) {
        if(IsServer()) {
          _server_state->current_phase_log->message_offsets.append(calc);
          int msg_length = _state->next_messages.contains(idx) ?
            _state->next_messages[idx] : 0;
          calc += msg_length;
        }
      }
    }

    foreach(int owner, _state->next_messages.keys()) {
      int msg_length = _state->next_messages[owner];

      QByteArray msg_ppp = QByteArray::fromRawData(
          _state->cleartext.constData() + offset, msg_length);
      offset += msg_length;

      QByteArray msg_pp = Derandomize(msg_ppp);
      if(msg_pp.isEmpty()) {
        qDebug() << "No message at" << owner;
        next_msg_length += msg_length;
        next_msgs[owner] = msg_length;

        if(_state->my_idx == owner) {
          _state->read = false;
          _state->slot_open = true;
          qDebug() << "My message didn't make it in time.";
        }
        continue;
      }

      if(msg_pp[0] != char(0)) {
        _state->start_accuse = true;
        if(owner == _state->my_idx) {
          _state->my_accuse = true;
        }
        qDebug() << "Accusation generated by" << owner;
      }
      
#ifdef CSBR_SIGN_SLOTS
      QSharedPointer<AsymmetricKey> vkey(_state->anonymous_keys[owner]);
      int sig_length = vkey->GetSignatureLength();
#endif

      QByteArray msg_p = QByteArray::fromRawData(
          msg_pp.constData() + 1, msg_pp.size() - 1 - sig_length);
      QByteArray sig = QByteArray::fromRawData(
          msg_pp.constData() + 1 + msg_p.size(), sig_length);

#ifdef CSBR_SIGN_SLOTS
      if(!vkey->Verify(msg_p, sig)) {
#else
      if(hash->ComputeHash(msg_p) != sig) {
#endif
        
        qDebug() << "Unable to verify message for peer at" << owner;
        next_msg_length += msg_length;
        next_msgs[owner] = msg_length;

        if(owner == _state->my_idx && !_state->accuse) {
          _state->read = false;
          _state->slot_open = true;
          _state->accuse = false;
          for(int pidx = 0; pidx < msg_ppp.size(); pidx++) {
            const char expected = _state->last_ciphertext[pidx];
            const char actual = msg_ppp[pidx];
            if(expected == actual) {
              continue;
            }
            for(int bidx = 0; bidx < 8; bidx++) {
              const char expected_bit = expected & bit_masks[bidx];
              if(expected_bit != 0) {
                continue;
              }
              const char actual_bit = actual & bit_masks[bidx];
              if(actual_bit == expected_bit) {
                continue;
              }
              _state->accuse_idx = (offset - msg_length + pidx) * 8 + bidx;
              _state->accuse = true;
              _state->blame_phase = _state_machine.GetPhase();
              break;
            }

            if(_state->accuse) {
              break;
            }
          }
          if(_state->accuse) {
            qDebug() << "My message got corrupted, blaming" <<
              _state->accuse_idx << _state->blame_phase;
          } else {
            qDebug() << "My message got corrupted cannot blame";
          }
        }
        continue;
      }

      int phase = Serialization::ReadInt(msg_p, 0);
      if(phase != _state_machine.GetPhase()) {
        next_msg_length += msg_length;
        next_msgs[owner] = msg_length;
        qDebug() << "Incorrect phase, skipping message";
        continue;
      }

      int next = Serialization::ReadInt(msg_p, 4);
      if(next < 0) {
        next_msg_length += msg_length;
        next_msgs[owner] = msg_length;
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

    if(IsServer()) {
      _server_state->current_phase_log->message_length = offset;
    }

    _state->next_messages = next_msgs;
    _state->msg_length = next_msg_length;
  }

  QByteArray CSBulkRound::NullSeed()
  {
    static QByteArray null_seed(
        CryptoFactory::GetInstance().GetLibrary()->RngOptimalSeedSize(), 0);
    return null_seed;
  }

  QByteArray CSBulkRound::Randomize(const QByteArray &msg)
  {
    Library *lib = CryptoFactory::GetInstance().GetLibrary();

    QSharedPointer<Random> rng0(lib->GetRandomNumberGenerator());
    QByteArray seed(lib->RngOptimalSeedSize(), 0);
    do {
      rng0->GenerateBlock(seed);
    } while(seed == NullSeed());

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

    if(seed == NullSeed()) {
      return QByteArray();
    }

    QSharedPointer<Random> rng(lib->GetRandomNumberGenerator(seed));

    QByteArray msg = QByteArray::fromRawData(
        randomized_text.constData() + seed.size(),
        randomized_text.size() - seed.size());

    QByteArray random_text(msg.size(), 0);
    rng->GenerateBlock(random_text);

    Xor(random_text, random_text, msg);
    return random_text;
  }

  QPair<int, QBitArray> CSBulkRound::FindMismatch()
  {
    QBitArray actual(GetGroup().Count(), false);
    QBitArray expected(GetGroup().Count(), false);
    foreach(const Id &key, _server_state->blame_bits.keys()) {
      const QPair<QBitArray, QBitArray> &pair = _server_state->blame_bits[key];
      actual ^= pair.first;
      expected ^= pair.second;
    }

    if(actual == expected) {
      throw QRunTimeError("False accusation");
    }
    QBitArray mismatch = (actual ^ expected);
    bool first_found = false;
    int first = -1;
    for(int idx = 0; idx < mismatch.size(); idx++) {
      if(mismatch.at(idx)) {
        qDebug() << "Found a mismatch at" << idx;
        if(!first_found) {
          first_found = true;
          first = idx;
        }
      }
    }

    if(!first_found) {
      return QPair<int, QBitArray>(-1, QBitArray());
    }

    QBitArray server_bits(_server_state->blame_bits.size(), false);
    int idx = 0;
    foreach(const PublicIdentity &pid, GetGroup().GetSubgroup()) {
      const QPair<QBitArray, QBitArray> &pair = _server_state->blame_bits[pid.GetId()];
      server_bits[idx++] = pair.second.at(first);
    }

    return QPair<int, QBitArray>(first, server_bits);
  }

  QPair<int, QByteArray> CSBulkRound::GetRebuttal(int phase, int accuse_idx,
      const QBitArray &server_bits)
  {
    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QSharedPointer<Hash> hashalgo(lib->GetHashAlgorithm());

    QByteArray bphase(4, 0);
    Serialization::WriteInt(phase, bphase, 0);

    QVector<QSharedPointer<Random> > rngs;
    int msg_size = accuse_idx / 8 + (accuse_idx % 8 > 0 ? 1 : 0);
    int bidx = -1;
    QByteArray tmp(msg_size, 0);
    for(int idx = 0; idx < _state->base_seeds.size(); idx++) {
      const QByteArray &base_seed = _state->base_seeds[idx];
      hashalgo->Update(base_seed);
      hashalgo->Update(bphase);
      hashalgo->Update(GetRoundId().GetByteArray());
      QByteArray seed = hashalgo->ComputeHash();
      QSharedPointer<Random> rng(lib->GetRandomNumberGenerator(seed));
      rng->GenerateBlock(tmp);
      if(((tmp[accuse_idx / 8] & bit_masks[accuse_idx % 8]) != 0) != server_bits[idx]) {
        bidx = idx;
        break;
      }
    }

    if(bidx >= 0) {
      qDebug() << "Found the mismatch!" << bidx;
    } else {
      bidx = phase % GetGroup().GetSubgroup().Count();
      qDebug() << "We gotz busted, blaming" << bidx;
    }

    Id bid = GetGroup().GetSubgroup().GetId(bidx);
    QByteArray server_dh = GetGroup().GetIdentity(bid).GetDhKey();
    QByteArray proof = GetPrivateIdentity().GetDhKey()->ProveSharedSecret(server_dh);
    return QPair<int, QByteArray>(bidx, proof);
  }
}
}
