#include <QDebug>

#include "Connections/IOverlaySender.hpp"
#include "Crypto/AsymmetricKey.hpp"
#include "Crypto/CryptoRandom.hpp"
#include "Crypto/Hash.hpp"
#include "Messaging/ISender.hpp"
#include "Messaging/StateData.hpp"
#include "Utils/QRunTimeError.hpp"
#include "Utils/Timer.hpp"
#include "Utils/TimerCallback.hpp"

#include "SessionData.hpp"
#include "ServerEnlisted.hpp"
#include "ServerList.hpp"
#include "ServerSession.hpp"
#include "ServerStart.hpp"
#include "ServerStop.hpp"
#include "ServerVerifyList.hpp"

#include "SessionMessage.hpp"
#include "SessionSharedState.hpp"
#include "SessionState.hpp"

namespace Dissent {
namespace Session {
namespace Server {
  class ServerSessionSharedState : public SessionSharedState {
    public:
      explicit ServerSessionSharedState(const QSharedPointer<ClientServer::Overlay> &overlay,
          const QSharedPointer<Crypto::AsymmetricKey> &my_key,
          const QSharedPointer<Crypto::KeyShare> &keys,
          Anonymity::CreateRound create_round) :
        SessionSharedState(overlay, my_key, keys, create_round)
      {
      }

      virtual ~ServerSessionSharedState() {}

      /**
       * Returns if the server is the proposer
       */
      bool IsProposer() const
      {
        return GetOverlay()->GetId() == GetOverlay()->GetServerIds().first();
      }

      Connections::Id GetProposer() const
      {
        return GetOverlay()->GetServerIds().first();
      }

      void CheckClientRegister(const ClientRegister &clr)
      {
        if(clr.GetRoundId() != GetRoundId()) {
          throw Utils::QRunTimeError("RoundId mismatch. Expected: " +
              GetRoundId().toBase64() + ", found: " +
              clr.GetRoundId().toBase64() + ", from " +
              clr.GetId().ToString());
        }

        QSharedPointer<Crypto::AsymmetricKey> key =
          GetKeyShare()->GetKey(clr.GetId().ToString());

        if(!key) {
          throw Utils::QRunTimeError("No such client: " + clr.GetId().ToString());
        }

        if(!key->Verify(clr.GetPayload(), clr.GetSignature())) {
          throw Utils::QRunTimeError("Invalid signature: " +
              clr.GetId().ToString());
        }

        if(!clr.GetKey()->IsValid()) {
          throw Utils::QRunTimeError("Invalid Ephemeral Key: " +
              clr.GetId().ToString());
        }
      }

      void Reset()
      {
        m_init.clear();
        m_enlist_msgs.clear();
        m_agree_msgs.clear();
        m_agree.clear();
        m_registered_msgs.clear();
        m_verify.clear();
        SetRoundId(QByteArray());
      }

      Messaging::State::ProcessResult DefaultHandleDisconnection(
          const Connections::Id &id)
      {
        if(GetOverlay()->IsServer(id)) {
          qDebug() << GetOverlay()->GetId() << "Server stopped:" <<
            id << "sending ServerStop";

          QByteArray round_id = GetRoundId();
          if(round_id.isEmpty()) {
            round_id = GetInit()->GetNonce();
          }

          ServerStop stop(GetOverlay()->GetId(), round_id, true,
              "Server disconnected: " + id.ToString());
          stop.SetSignature(GetPrivateKey()->Sign(stop.GetPayload()));

          GetOverlay()->Broadcast("SessionData", stop.GetPacket());
        }
        return Messaging::State::NoChange;
      }

      virtual bool CheckServerStop(const ServerStop &stop)
      {
        if(stop.GetRoundId().isEmpty()) {
          throw Utils::QRunTimeError("Invalid RoundId");
        }

        QSharedPointer<Crypto::AsymmetricKey> key =
          GetKeyShare()->GetKey(stop.GetId().ToString());
        if(!key->Verify(stop.GetPayload(), stop.GetSignature())) {
          throw Utils::QRunTimeError("Invalid signature");
        }

        QByteArray round_id = GetRoundId();
        if(round_id.isEmpty()) {
          round_id = GetInit()->GetNonce();
        }

        if((GetRoundId() != stop.GetRoundId()) &&
            (GetInit() && (GetInit()->GetNonce() != stop.GetRoundId())))
        {
          QString expected = (GetInit() ? GetInit()->GetNonce().toBase64() : "")
            + " or " + GetRoundId().toBase64();

          throw Utils::QRunTimeError("RoundId mismatch. Expected: " +
              expected + ", found: " +
              stop.GetRoundId().toBase64() + ", from " +
              stop.GetId().ToString());
        }

        QString round = GetRoundId().isEmpty() ? "Enlist:" : "Round:";
        qDebug() << GetOverlay()->GetId() << "Stopping" << round <<
          stop.GetRoundId().toBase64() << "Reason:" << stop.GetReason() <<
          "Immediately: " << stop.GetImmediate();
        return stop.GetImmediate();
      }

      void SetInit(const QSharedPointer<ServerInit> &init) { m_init = init; }
      QSharedPointer<ServerInit> GetInit() const { return m_init; }

      typedef QMap<Connections::Id, QSharedPointer<ServerEnlist> > EnlistMap;
      void SetEnlistMsgs(const EnlistMap &map) { m_enlist_msgs = map; }
      EnlistMap GetEnlistMsgs() const { return m_enlist_msgs; }

      typedef QMap<Connections::Id, QSharedPointer<ServerAgree> > AgreeMap;
      void SetAgreeMsgs(const AgreeMap &map) {m_agree_msgs = map; }
      AgreeMap GetAgreeMsgs() const { return m_agree_msgs; }
      QByteArray GetAgree() const { return m_agree; }

      typedef QMap<Connections::Id, QSharedPointer<ClientRegister> > RegisterMap;
      void SetClientRegisterMsgs(const RegisterMap &map) { m_registered_msgs = map; }
      RegisterMap GetClientRegisterMsgs() const { return m_registered_msgs; }

      typedef QMap<Connections::Id, QByteArray> VerifyMap;
      void SetVerifyMap(const VerifyMap &map) { m_verify = map; }
      VerifyMap GetVerifyMap() const { return m_verify; }
      
    private:
      QSharedPointer<ServerInit> m_init;
      EnlistMap m_enlist_msgs;
      AgreeMap m_agree_msgs;
      QByteArray m_agree;
      RegisterMap m_registered_msgs;
      VerifyMap m_verify;
  };

  class OfflineState : public SessionState {
    public:
      OfflineState(const QSharedPointer<Messaging::StateData> &data) :
        SessionState(data,
            SessionStates::Offline,
            SessionMessage::None)
      {
        AddMessageProcessor(SessionMessage::ServerInit,
            QSharedPointer<StateCallback>(new StateCallbackImpl<OfflineState>(this,
                &OfflineState::HandleServerInit)));
        AddMessageProcessor(SessionMessage::ServerStop,
            QSharedPointer<StateCallback>(new StateCallbackImpl<OfflineState>(this,
                &OfflineState::HandleServerStop)));
      }

    private:
      ProcessResult HandleServerInit(
          const QSharedPointer<Messaging::ISender> &,
          const QSharedPointer<Messaging::Message> &)
      {
        return StoreMessage;
      }

      ProcessResult HandleServerStop(
          const QSharedPointer<Messaging::ISender> &,
          const QSharedPointer<Messaging::Message> &)
      {
        return StoreMessage;
      }
  };

  class WaitingForServersState : public SessionState {
    public:
      WaitingForServersState(const QSharedPointer<Messaging::StateData> &data) :
        SessionState(data,
            SessionStates::WaitingForServers,
            SessionMessage::None)
      {
        AddMessageProcessor(SessionMessage::ServerInit,
            QSharedPointer<StateCallback>(new StateCallbackImpl<WaitingForServersState>(this,
                &WaitingForServersState::HandleServerInit)));
        AddMessageProcessor(SessionMessage::ServerStop,
            QSharedPointer<StateCallback>(new StateCallbackImpl<WaitingForServersState>(this,
                &WaitingForServersState::HandleServerStop)));
      }

      virtual ProcessResult Init()
      {
        QSharedPointer<ServerSessionSharedState> state =
          GetSharedState().dynamicCast<ServerSessionSharedState>();
        state->Reset();

        if(CheckServers()) {
          return NextState;
        }
        return NoChange;
      }

      virtual ProcessResult HandleConnection(const Connections::Id &remote)
      {
        QSharedPointer<ServerSessionSharedState> state =
          GetSharedState().dynamicCast<ServerSessionSharedState>();

        if(state->GetOverlay()->IsServer(remote) && CheckServers()) {
          return NextState;
        }
        return NoChange;
      }

    private:
      ProcessResult HandleServerInit(
          const QSharedPointer<Messaging::ISender> &,
          const QSharedPointer<Messaging::Message> &)
      {
        return StoreMessage;
      }

      ProcessResult HandleServerStop(
          const QSharedPointer<Messaging::ISender> &,
          const QSharedPointer<Messaging::Message> &)
      {
        return StoreMessage;
      }

      bool CheckServers()
      {
        QSharedPointer<ServerSessionSharedState> state =
          GetSharedState().dynamicCast<ServerSessionSharedState>();

        int connected_servers = 0;

        Connections::ConnectionTable &ct = state->GetOverlay()->GetConnectionTable();
        foreach(const QSharedPointer<Connections::Connection> &con, ct.GetConnections()) {
          if(state->GetOverlay()->IsServer(con->GetRemoteId())) {
            connected_servers++;
          }
        }

        if(connected_servers != state->GetOverlay()->GetServerIds().count()) {
          qDebug() << "Server" << state->GetOverlay()->GetId() << "connected to" <<
            connected_servers << "of" << state->GetOverlay()->GetServerIds().count() <<
            "servers.";
          return false;
        }

        return true;
      }
  };

  class InitState : public SessionState {
    public:
      InitState(const QSharedPointer<Messaging::StateData> &data) :
        SessionState(data,
            SessionStates::Init,
            SessionMessage::ServerInit)
      {
        AddMessageProcessor(SessionMessage::ServerStop,
            QSharedPointer<StateCallback>(new StateCallbackImpl<InitState>(this,
                &InitState::HandleServerStop)));
      }

      virtual ProcessResult Init()
      {
        QSharedPointer<ServerSessionSharedState> state =
          GetSharedState().dynamicCast<ServerSessionSharedState>();

        if(!state->IsProposer()) {
          return NoChange;
        }

        qDebug() << state->GetOverlay()->GetId() << this << "sending" <<
          SessionMessage::MessageTypeToString(GetMessageType());

        QByteArray nonce(16, 0);
        Crypto::CryptoRandom rand;
        rand.GenerateBlock(nonce);
        qint64 ctime = Utils::Time::GetInstance().MSecsSinceEpoch();
        // @TODO compute GroupId
        QSharedPointer<ServerInit> init(new ServerInit(
              state->GetOverlay()->GetId(), nonce, ctime, QByteArray(16, 0)));
        init->SetSignature(state->GetPrivateKey()->Sign(init->GetPayload()));
        state->SetInit(init);

        foreach(const Connections::Id &remote_id, state->GetOverlay()->GetServerIds()) {
          if(remote_id == state->GetProposer()) {
            continue;
          }
          state->GetOverlay()->SendNotification(remote_id, "SessionData", init->GetPacket());
        }
        return NextState;
      }

      virtual ProcessResult ProcessPacket(
          const QSharedPointer<Messaging::ISender> &,
          const QSharedPointer<Messaging::Message> &msg)
      {
        QSharedPointer<ServerSessionSharedState> state =
          GetSharedState().dynamicCast<ServerSessionSharedState>();

        QSharedPointer<ServerInit> init = msg.dynamicCast<ServerInit>();
        Connections::Id first = state->GetOverlay()->GetServerIds().first();
        if(init->GetId() != first) {
          throw Utils::QRunTimeError("Expected: " + first.ToString() +
              ", got: " + init->GetId().ToString());
        }

        QSharedPointer<Crypto::AsymmetricKey> key =
          state->GetKeyShare()->GetKey(first.ToString());

        if(!key->Verify(init->GetPayload(), init->GetSignature())) {
          throw Utils::QRunTimeError("Invalid signature");
        }

        QSharedPointer<ServerInit> c_init = state->GetInit();
        if(c_init) {
          if(c_init->GetTimestamp() > init->GetTimestamp()) {
            throw Utils::QRunTimeError("Old init: " +
                QString::number(c_init->GetTimestamp()) +
                " > " +
                QString::number(init->GetTimestamp()));
          } else if(c_init->GetPacket() == init->GetPacket()) {
            return NoChange;
          }
        }

        state->SetInit(init);
        return NextState;
      }

      virtual ProcessResult HandleDisconnection(const Connections::Id &id)
      {
        QSharedPointer<SessionSharedState> state =
          GetSharedState().dynamicCast<SessionSharedState>();

        if(state->GetOverlay()->IsServer(id)) {
          qDebug() << state->GetOverlay()->GetId() << "no active setup phase," <<
            "waiting for reconnection.";
          return Restart;
        }
        return NoChange;
      }

    private:
      ProcessResult HandleServerStop(
          const QSharedPointer<Messaging::ISender> &,
          const QSharedPointer<Messaging::Message> &)
      {
        return StoreMessage;
      }
  };

  class EnlistState : public SessionState {
    public:
      EnlistState(const QSharedPointer<Messaging::StateData> &data) :
        SessionState(data,
            SessionStates::Enlist,
            SessionMessage::ServerEnlisted)
      {
        AddMessageProcessor(SessionMessage::ServerAgree,
            QSharedPointer<StateCallback>(new StateCallbackImpl<EnlistState>(this,
                &EnlistState::HandleServerAgree)));
        AddMessageProcessor(SessionMessage::ServerEnlist,
            QSharedPointer<StateCallback>(new StateCallbackImpl<EnlistState>(this,
                &EnlistState::HandleServerEnlist)));

        QSharedPointer<SessionSharedState> state =
          GetSharedState().dynamicCast<SessionSharedState>();
        AddMessageProcessor(SessionMessage::ServerStop,
            QSharedPointer<StateCallback>(new StateCallbackImpl<SessionSharedState>(
                state.data(), &SessionSharedState::DefaultHandleServerStop)));
      }

      virtual ProcessResult Init()
      {
        QSharedPointer<ServerSessionSharedState> state =
          GetSharedState().dynamicCast<ServerSessionSharedState>();
        qDebug() << state->GetOverlay()->GetId() << this << "sending" <<
          SessionMessage::MessageTypeToString(SessionMessage::ServerEnlist);

        state->GenerateRoundData();

        ServerEnlist enlist(state->GetOverlay()->GetId(),
            state->GetInit(), state->GetEphemeralKey()->GetPublicKey(),
            state->GetOptionalPublic());
        enlist.SetSignature(state->GetPrivateKey()->Sign(enlist.GetPayload()));

        state->GetOverlay()->SendNotification(state->GetProposer(),
            "SessionData", enlist.GetPacket());
        return NoChange;
      }

      virtual ProcessResult ProcessPacket(
          const QSharedPointer<Messaging::ISender> &,
          const QSharedPointer<Messaging::Message> &msg)
      {
        QSharedPointer<ServerSessionSharedState> state =
          GetSharedState().dynamicCast<ServerSessionSharedState>();
        QSharedPointer<ServerEnlisted> enlisted = msg.dynamicCast<ServerEnlisted>();

        QSharedPointer<Crypto::AsymmetricKey> key =
          state->GetKeyShare()->GetKey(state->GetProposer().ToString());
        if(!key->Verify(enlisted->GetPayload(), enlisted->GetSignature())) {
          throw Utils::QRunTimeError("Invalid signature");
        }

        int expected = state->GetOverlay()->GetServerIds().size();
        int found = enlisted->GetEnlists().size();
        if(expected != found) {
          throw Utils::QRunTimeError("Expected " + QString::number(expected) +
             " ServerEnlists found " + QString::number(found));
        }

        foreach(const QSharedPointer<ServerEnlist> &enlist, enlisted->GetEnlists()) {
          VerifyEnlist(enlist);
        }
        return NextState;
      }

      virtual ProcessResult HandleDisconnection(const Connections::Id &id)
      {
        QSharedPointer<ServerSessionSharedState> state =
          GetSharedState().dynamicCast<ServerSessionSharedState>();
        return state->DefaultHandleDisconnection(id);
      }

    private:
      ProcessResult HandleServerEnlist(
          const QSharedPointer<Messaging::ISender> &,
          const QSharedPointer<Messaging::Message> &msg)
      {
        QSharedPointer<ServerSessionSharedState> state =
          GetSharedState().dynamicCast<ServerSessionSharedState>();
        if(state->IsProposer()) {
          return VerifyEnlist(msg.dynamicCast<ServerEnlist>());
        } else {
          throw Utils::QRunTimeError("Unexpected");
        }
      }
      
      ProcessResult VerifyEnlist(const QSharedPointer<ServerEnlist> &msg)
      {
        QSharedPointer<ServerSessionSharedState> state =
          GetSharedState().dynamicCast<ServerSessionSharedState>();

        QSharedPointer<ServerEnlist> enlist = msg.dynamicCast<ServerEnlist>();
        Connections::Id remote_id = enlist->GetId();

        if(!state->GetOverlay()->IsServer(remote_id)) {
          throw Utils::QRunTimeError("Not a server: " + remote_id.ToString());
        }

        if(state->GetInit()->GetPacket() != enlist->GetInit()->GetPacket()) {
          throw Utils::QRunTimeError("Invalid ServerInit");
        }

        // This is just a repeat of the current init message with no new state
        if(m_enlist_msgs.contains(remote_id)) {
          throw Utils::QRunTimeError("Already have Enlist message from " +
              remote_id.ToString());
        }

        if(!state->GetKeyShare()->GetKey(remote_id.ToString())->Verify(enlist->GetPayload(),
              enlist->GetSignature()))
        {
          throw Utils::QRunTimeError("Invalid signature from " + remote_id.ToString());
        }

        if(!enlist->GetKey()->IsValid()) {
          throw Utils::QRunTimeError("Invalid Ephemeral Key from " + remote_id.ToString());
        }

        m_enlist_msgs[remote_id] = enlist;
        if(m_enlist_msgs.count() != state->GetOverlay()->GetServerIds().size()) {
          qDebug() << state->GetOverlay()->GetId() << this << "from" <<
            enlist->GetId() << "have" << m_enlist_msgs.count() << "of" <<
            state->GetOverlay()->GetServerIds().size();
          return NoChange;
        }

        state->SetEnlistMsgs(m_enlist_msgs);

        ServerEnlisted enlisted(m_enlist_msgs.values());
        enlisted.SetSignature(state->GetPrivateKey()->Sign(enlisted.GetPayload()));
        foreach(const Connections::Id &remote_id, state->GetOverlay()->GetServerIds()) {
          if(remote_id == state->GetProposer()) {
            continue;
          }
          state->GetOverlay()->SendNotification(remote_id, "SessionData", enlisted.GetPacket());
        }

        return NextState;
      }

      ProcessResult HandleServerAgree(
          const QSharedPointer<Messaging::ISender> &,
          const QSharedPointer<Messaging::Message> &)
      {
        return StoreMessage;
      }

      ServerSessionSharedState::EnlistMap m_enlist_msgs;

  };

  class AgreeState : public SessionState {
    public:
      AgreeState(const QSharedPointer<Messaging::StateData> &data) :
        SessionState(data,
            SessionStates::Agree,
            SessionMessage::ServerAgree)
      {
        AddMessageProcessor(SessionMessage::ClientRegister,
            QSharedPointer<StateCallback>(new StateCallbackImpl<AgreeState>(this,
                &AgreeState::HandleClientRegister)));
        AddMessageProcessor(SessionMessage::ServerList,
            QSharedPointer<StateCallback>(new StateCallbackImpl<AgreeState>(this,
                &AgreeState::HandleServerList)));

        QSharedPointer<ServerSessionSharedState> state =
          GetSharedState().dynamicCast<ServerSessionSharedState>();
        AddMessageProcessor(SessionMessage::ServerStop,
            QSharedPointer<StateCallback>(new StateCallbackImpl<SessionSharedState>(
                state.data(), &SessionSharedState::DefaultHandleServerStop)));
      }

      virtual ProcessResult Init()
      {
        QSharedPointer<ServerSessionSharedState> state =
          GetSharedState().dynamicCast<ServerSessionSharedState>();

        Crypto::Hash hash;
        foreach(const QSharedPointer<ServerEnlist> &enlist, state->GetEnlistMsgs()) {
          hash.Update(enlist->GetPayload());
        }

        state->SetRoundId(hash.ComputeHash());
        ServerAgree agree(state->GetOverlay()->GetId(),
            state->GetRoundId(), state->GetEphemeralKey()->GetPublicKey(),
            state->GetOptionalPublic());
        agree.SetSignature(state->GetPrivateKey()->Sign(agree.GetPayload()));

        foreach(const Connections::Id &remote_id, state->GetOverlay()->GetServerIds()) {
          state->GetOverlay()->SendNotification(remote_id, "SessionData", agree.GetPacket());
        }

        return NoChange;
      }

      virtual ProcessResult ProcessPacket(
          const QSharedPointer<Messaging::ISender> &,
          const QSharedPointer<Messaging::Message> &msg)
      {
        QSharedPointer<ServerSessionSharedState> state =
          GetSharedState().dynamicCast<ServerSessionSharedState>();
        QSharedPointer<ServerAgree> agree = msg.dynamicCast<ServerAgree>();

        Connections::Id remote_id = agree->GetId();
        if(!state->GetOverlay()->IsServer(remote_id)) {
          throw Utils::QRunTimeError("Not a server: " + remote_id.ToString());
        }

        if(m_agree_msgs.contains(remote_id)) {
          throw Utils::QRunTimeError("Already have Agree message: " +
              remote_id.ToString());
        }

        state->CheckServerAgree(*agree, state->GetRoundId());

        QSharedPointer<ServerEnlist> enlist = state->GetEnlistMsgs()[remote_id];
        if((enlist->GetId() != agree->GetId()) ||
            (enlist->GetKey() != agree->GetKey()) ||
            (enlist->GetOptional() != agree->GetOptional()))
        {
          throw Utils::QRunTimeError("Agree message doesn't match Enlist: " +
              remote_id.ToString());
        }

        m_agree_msgs[remote_id] = agree;
        if(m_agree_msgs.count() != state->GetOverlay()->GetServerIds().size()) {
          qDebug() << state->GetOverlay()->GetId() << this << "have" <<
            m_agree_msgs.count() << "of" <<
            state->GetOverlay()->GetServerIds().size();
          return NoChange;
        }

        state->SetAgreeMsgs(m_agree_msgs);
        state->SetServers(m_agree_msgs.values());
        return NextState;
      }

      virtual ProcessResult HandleDisconnection(const Connections::Id &id)
      {
        QSharedPointer<ServerSessionSharedState> state =
          GetSharedState().dynamicCast<ServerSessionSharedState>();
        return state->DefaultHandleDisconnection(id);
      }

    private:
      ProcessResult HandleClientRegister(
          const QSharedPointer<Messaging::ISender> &,
          const QSharedPointer<Messaging::Message> &)
      {
        return StoreMessage;
      }

      ProcessResult HandleServerList(
          const QSharedPointer<Messaging::ISender> &,
          const QSharedPointer<Messaging::Message> &)
      {
        return StoreMessage;
      }

      ServerSessionSharedState::AgreeMap m_agree_msgs;
  };

  class RegisteringState : public SessionState {
    public:
      RegisteringState(const QSharedPointer<Messaging::StateData> &data) :
        SessionState(data,
            SessionStates::Registering,
            SessionMessage::ClientRegister)
      {
        AddMessageProcessor(SessionMessage::ServerList,
            QSharedPointer<StateCallback>(new StateCallbackImpl<RegisteringState>(this,
                &RegisteringState::HandleServerList)));

        QSharedPointer<SessionSharedState> state =
          GetSharedState().dynamicCast<SessionSharedState>();
        AddMessageProcessor(SessionMessage::ServerStop,
            QSharedPointer<StateCallback>(new StateCallbackImpl<SessionSharedState>(
                state.data(), &SessionSharedState::DefaultHandleServerStop)));
      }

      ~RegisteringState()
      {
        m_register_timer.Stop();
      }

      virtual ProcessResult Init()
      {
        QSharedPointer<ServerSessionSharedState> state =
          GetSharedState().dynamicCast<ServerSessionSharedState>();

        qDebug() << state->GetOverlay()->GetId() << this << "sending" <<
          SessionMessage::MessageTypeToString(SessionMessage::ServerQueued);

        Utils::TimerCallback *cb =
          new Utils::TimerMethod<RegisteringState, int>(this,
              &RegisteringState::FinishClientRegister, 0);
        m_register_timer = Utils::Timer::GetInstance().QueueCallback(cb, ROUND_TIMER);

        ServerQueued queued(state->GetServers(), QByteArray(16, 0),
            state->GetServersBytes());
        queued.SetSignature(state->GetPrivateKey()->Sign(queued.GetPayload()));

        Connections::ConnectionTable &ct = state->GetOverlay()->GetConnectionTable();
        foreach(const QSharedPointer<Connections::Connection> &con, ct.GetConnections()) {
          Connections::Id remote_id = con->GetRemoteId();
          if(state->GetOverlay()->IsServer(remote_id)) {
            continue;
          }
          state->GetOverlay()->SendNotification(remote_id, "SessionData", queued.GetPacket());
        }

        return NoChange;
      }

      virtual ProcessResult ProcessPacket(
          const QSharedPointer<Messaging::ISender> &,
          const QSharedPointer<Messaging::Message> &msg)
      {
        QSharedPointer<ServerSessionSharedState> state =
          GetSharedState().dynamicCast<ServerSessionSharedState>();
        QSharedPointer<ClientRegister> clr = msg.dynamicCast<ClientRegister>();

        Connections::Id remote_id = clr->GetId();
        if(state->GetOverlay()->IsServer(remote_id)) {
          throw Utils::QRunTimeError("Is server: " + remote_id.ToString());
        }

        if(m_registered_msgs.contains(remote_id)) {
          throw Utils::QRunTimeError("Already registered: " + remote_id.ToString());
        }

        state->CheckClientRegister(*clr);
        m_registered_msgs[remote_id] = clr;
        qDebug() << state->GetOverlay()->GetId() << this << remote_id << "registered";
        return NoChange;
      }

      virtual ProcessResult HandleConnection(const Connections::Id &remote)
      {
        QSharedPointer<ServerSessionSharedState> state =
          GetSharedState().dynamicCast<ServerSessionSharedState>();
        ServerQueued queued(state->GetServers(), QByteArray(16, 0),
            state->GetServersBytes());
        queued.SetSignature(state->GetPrivateKey()->Sign(queued.GetPayload()));
        state->GetOverlay()->SendNotification(remote, "SessionData", queued.GetPacket());
        return NoChange;
      }

      // @TODO Add a HandleConnection and pass the server messages downstream
      virtual ProcessResult HandleDisconnection(const Connections::Id &id)
      {
        QSharedPointer<ServerSessionSharedState> state =
          GetSharedState().dynamicCast<ServerSessionSharedState>();
        return state->DefaultHandleDisconnection(id);
      }

    private:
      ProcessResult HandleServerList(
          const QSharedPointer<Messaging::ISender> &,
          const QSharedPointer<Messaging::Message> &)
      {
        return StoreMessage;
      }

      /**
       * Called after the timeout for the client registration phase has passed
       */
      void FinishClientRegister(const int &)
      {
        QSharedPointer<ServerSessionSharedState> state =
          GetSharedState().dynamicCast<ServerSessionSharedState>();
        qDebug() << state->GetOverlay()->GetId() << this <<
          "finished waiting for client.";

        state->SetClientRegisterMsgs(m_registered_msgs);
        StateChange(NextState);
      }

      int ROUND_TIMER = 30 * 1000;
      Utils::TimerEvent m_register_timer;
      ServerSessionSharedState::RegisterMap m_registered_msgs;
  };

  class ListExchangeState : public SessionState {
    public:
      ListExchangeState(const QSharedPointer<Messaging::StateData> &data) :
        SessionState(data,
            SessionStates::ListExchange,
            SessionMessage::ServerList)
      {
        AddMessageProcessor(SessionMessage::ServerVerifyList,
            QSharedPointer<StateCallback>(new StateCallbackImpl<ListExchangeState>(this,
                &ListExchangeState::HandleServerVerifyList)));

        QSharedPointer<SessionSharedState> state =
          GetSharedState().dynamicCast<SessionSharedState>();
        AddMessageProcessor(SessionMessage::ServerStop,
            QSharedPointer<StateCallback>(new StateCallbackImpl<SessionSharedState>(
                state.data(), &SessionSharedState::DefaultHandleServerStop)));
      }

      virtual ProcessResult Init()
      {
        QSharedPointer<ServerSessionSharedState> state =
          GetSharedState().dynamicCast<ServerSessionSharedState>();
        m_registered_msgs = state->GetClientRegisterMsgs();
        qDebug() << state->GetOverlay()->GetId() << this << "sending" <<
          SessionMessage::MessageTypeToString(GetMessageType());

        ServerList list(state->GetClientRegisterMsgs().values());
        list.SetSignature(state->GetPrivateKey()->Sign(list.GetPayload()));

        foreach(const Connections::Id &remote_id, state->GetOverlay()->GetServerIds()) {
          state->GetOverlay()->SendNotification(remote_id, "SessionData", list.GetPacket());
        }
        return NoChange;
      }

      virtual ProcessResult ProcessPacket(
          const QSharedPointer<Messaging::ISender> &from,
          const QSharedPointer<Messaging::Message> &msg)
      {
        QSharedPointer<ServerSessionSharedState> state =
          GetSharedState().dynamicCast<ServerSessionSharedState>();
        QSharedPointer<ServerList> list = msg.dynamicCast<ServerList>();

        QSharedPointer<Connections::IOverlaySender> sender =
          from.dynamicCast<Connections::IOverlaySender>();

        if(!sender) {
          throw Utils::QRunTimeError("Bad sender: " + from->ToString());
        }

        Connections::Id remote_id = sender->GetRemoteId();
        if(!state->GetOverlay()->IsServer(remote_id)) {
          throw Utils::QRunTimeError("Non-server: " + remote_id.ToString());
        }

        if(m_list_received.contains(remote_id)) {
          throw Utils::QRunTimeError("Already have List: " +
              remote_id.ToString());
        }

        foreach(const QSharedPointer<ClientRegister> &clr, list->GetRegisterList()) {
          state->CheckClientRegister(*clr);
        }

        foreach(const QSharedPointer<ClientRegister> &clr, list->GetRegisterList()) {
          if(m_registered_msgs.contains(clr->GetId())) {
            // go with the lower server entry...
          }
          m_registered_msgs[clr->GetId()] = clr;
        }

        m_list_received[remote_id] = true;
        if(m_list_received.count() != state->GetOverlay()->GetServerIds().size()) {
          qDebug() << state->GetOverlay()->GetId() << this << "have" <<
            m_list_received.count() << "of" <<
            state->GetOverlay()->GetServerIds().size();
          return NoChange;
        }

        state->SetClientRegisterMsgs(m_registered_msgs);
        state->SetClients(m_registered_msgs.values());
        return NextState;
      }

      virtual ProcessResult HandleDisconnection(const Connections::Id &id)
      {
        QSharedPointer<ServerSessionSharedState> state =
          GetSharedState().dynamicCast<ServerSessionSharedState>();
        return state->DefaultHandleDisconnection(id);
      }

    private:
      ProcessResult HandleServerVerifyList(
          const QSharedPointer<Messaging::ISender> &,
          const QSharedPointer<Messaging::Message> &)
      {
        return StoreMessage;
      }

      QMap<Connections::Id, bool> m_list_received;
      ServerSessionSharedState::RegisterMap m_registered_msgs;
  };

  class VerifyListState : public SessionState {
    public:
      VerifyListState(const QSharedPointer<Messaging::StateData> &data) :
        SessionState(data,
            SessionStates::VerifyList,
            SessionMessage::ServerVerifyList)
      {
        AddMessageProcessor(SessionMessage::SessionData,
            QSharedPointer<StateCallback>(new StateCallbackImpl<VerifyListState>(this,
                &VerifyListState::HandleData)));

        QSharedPointer<SessionSharedState> state =
          GetSharedState().dynamicCast<SessionSharedState>();
        AddMessageProcessor(SessionMessage::ServerStop,
            QSharedPointer<StateCallback>(new StateCallbackImpl<SessionSharedState>(
                state.data(), &SessionSharedState::DefaultHandleServerStop)));
      }

      virtual ProcessResult Init()
      {
        QSharedPointer<ServerSessionSharedState> state =
          GetSharedState().dynamicCast<ServerSessionSharedState>();
        qDebug() << state->GetOverlay()->GetId() << this << "sending" <<
          SessionMessage::MessageTypeToString(GetMessageType());

        QByteArray registered = SerializeList<ClientRegister>(state->GetClients());
        Crypto::Hash hash;
        m_registered = hash.ComputeHash(registered);
        ServerVerifyList verify(state->GetPrivateKey()->Sign(m_registered), true);
        foreach(const Connections::Id &remote_id, state->GetOverlay()->GetServerIds()) {
          state->GetOverlay()->SendNotification(remote_id, "SessionData", verify.GetPacket());
        }

        return NoChange;
      }

      virtual ProcessResult ProcessPacket(
          const QSharedPointer<Messaging::ISender> &from,
          const QSharedPointer<Messaging::Message> &msg)
      {
        QSharedPointer<ServerSessionSharedState> state =
          GetSharedState().dynamicCast<ServerSessionSharedState>();

        QSharedPointer<Connections::IOverlaySender> sender =
          from.dynamicCast<Connections::IOverlaySender>();

        if(!sender) {
          throw Utils::QRunTimeError("Bad sender: " + from->ToString());
        }

        Connections::Id remote_id = sender->GetRemoteId();
        if(!state->GetOverlay()->IsServer(remote_id)) {
          throw Utils::QRunTimeError("Non-server: " + remote_id.ToString());
        }

        if(m_verify.contains(remote_id)) {
          throw Utils::QRunTimeError("Already have VerifyList: " +
              remote_id.ToString());
        }

        QSharedPointer<ServerVerifyList> verify =
          msg.dynamicCast<ServerVerifyList>();
        QSharedPointer<Crypto::AsymmetricKey> key =
          state->GetKeyShare()->GetKey(remote_id.ToString());
        QByteArray signature = verify->GetSignature();
        if(!key->Verify(m_registered, signature)) {
          throw Utils::QRunTimeError("Invalid signature: " +
              remote_id.ToString());
        }

        m_verify[remote_id] = signature;
        if(m_verify.count() != state->GetOverlay()->GetServerIds().size()) {
          qDebug() << state->GetOverlay()->GetId() << this << "have" <<
            m_verify.count() << "of" <<
            state->GetOverlay()->GetServerIds().size();
          return NoChange;
        }

        state->SetVerifyMap(m_verify);
        return NextState;
      }

      virtual ProcessResult HandleDisconnection(const Connections::Id &id)
      {
        QSharedPointer<ServerSessionSharedState> state =
          GetSharedState().dynamicCast<ServerSessionSharedState>();
        return state->DefaultHandleDisconnection(id);
      }

    private:
      ProcessResult HandleData(
          const QSharedPointer<Messaging::ISender> &,
          const QSharedPointer<Messaging::Message> &)
      {
        return StoreMessage;
      }

      ServerSessionSharedState::VerifyMap m_verify;
      QByteArray m_registered;
  };

  class CommState : public SessionState {
    public:
      explicit CommState(const QSharedPointer<Messaging::StateData> &data) :
        SessionState(data,
            SessionStates::Communicating,
            SessionMessage::SessionData)
      {
        AddMessageProcessor(SessionMessage::ServerInit,
            QSharedPointer<StateCallback>(new StateCallbackImpl<CommState>(this,
                &CommState::HandleServerInit)));

        QSharedPointer<SessionSharedState> state =
          GetSharedState().dynamicCast<SessionSharedState>();
        AddMessageProcessor(SessionMessage::ServerStop,
            QSharedPointer<StateCallback>(new StateCallbackImpl<SessionSharedState>(
                state.data(), &SessionSharedState::DefaultHandleServerStop)));
      }

      virtual ProcessResult Init()
      {
        QSharedPointer<ServerSessionSharedState> state =
          GetSharedState().dynamicCast<ServerSessionSharedState>();
        qDebug() << state->GetOverlay()->GetId() << this << "sending" <<
          SessionMessage::MessageTypeToString(SessionMessage::ServerStart);

        state->NextRound();

        ServerStart start(state->GetClients(), state->GetVerifyMap().values());
        Connections::ConnectionTable &ct = state->GetOverlay()->GetConnectionTable();
        foreach(const QSharedPointer<Connections::Connection> &con, ct.GetConnections()) {
          if(state->GetClientRegisterMsgs().contains(con->GetRemoteId())) {
            state->GetOverlay()->SendNotification(
                con->GetRemoteId(), "SessionData", start.GetPacket());
          }
        }

        state->GetRound()->Start();
        return NoChange;
      }

      virtual ProcessResult ProcessPacket(
          const QSharedPointer<Messaging::ISender> &from,
          const QSharedPointer<Messaging::Message> &msg)
      {
        QSharedPointer<SessionData> rm(msg.dynamicCast<SessionData>());
        if(!rm) {
          throw Utils::QRunTimeError("Invalid message");
        }

        QSharedPointer<Connections::IOverlaySender> sender =
          from.dynamicCast<Connections::IOverlaySender>();

        if(!sender) {
          throw Utils::QRunTimeError("Received wayward message from: " +
              from->ToString());
        }

        GetSharedState()->GetRound()->ProcessPacket(
            sender->GetRemoteId(), rm->GetPacket());
        return NoChange;
      }

      virtual ProcessResult HandleDisconnection(const Connections::Id &id)
      {
        QSharedPointer<ServerSessionSharedState> state =
          GetSharedState().dynamicCast<ServerSessionSharedState>();
        return state->DefaultHandleDisconnection(id);
      }

    private:
      ProcessResult HandleServerInit(
          const QSharedPointer<Messaging::ISender> &,
          const QSharedPointer<Messaging::Message> &)
      {
        return StoreMessage;
      }
  };
}

  using namespace Server;
  
  ServerSession::ServerSession(
          const QSharedPointer<ClientServer::Overlay> &overlay,
          const QSharedPointer<Crypto::AsymmetricKey> &my_key,
          const QSharedPointer<Crypto::KeyShare> &keys,
          Anonymity::CreateRound create_round) :
    Session(QSharedPointer<SessionSharedState>(
          new ServerSessionSharedState(overlay, my_key, keys, create_round)))
  {
    GetStateMachine().AddState(new Messaging::StateFactory<OfflineState>(
          SessionStates::Offline, SessionMessage::None));
    GetStateMachine().AddState(new Messaging::StateFactory<WaitingForServersState>(
          SessionStates::WaitingForServers, SessionMessage::None));
    GetStateMachine().AddState(new Messaging::StateFactory<InitState>(
          SessionStates::Init, SessionMessage::ServerInit));
    GetStateMachine().AddState(new Messaging::StateFactory<EnlistState>(
          SessionStates::Enlist, SessionMessage::ServerEnlisted));
    GetStateMachine().AddState(new Messaging::StateFactory<AgreeState>(
          SessionStates::Agree, SessionMessage::ServerAgree));
    GetStateMachine().AddState(new Messaging::StateFactory<RegisteringState>(
          SessionStates::Registering, SessionMessage::ClientRegister));
    GetStateMachine().AddState(new Messaging::StateFactory<ListExchangeState>(
          SessionStates::ListExchange, SessionMessage::ServerList));
    GetStateMachine().AddState(new Messaging::StateFactory<VerifyListState>(
          SessionStates::VerifyList, SessionMessage::ServerVerifyList));
    GetStateMachine().AddState(new Messaging::StateFactory<CommState>(
          SessionStates::Communicating, SessionMessage::SessionData));

    GetStateMachine().AddTransition(SessionStates::Offline,
        SessionStates::WaitingForServers);
    GetStateMachine().AddTransition(SessionStates::WaitingForServers,
        SessionStates::Init);
    GetStateMachine().AddTransition(SessionStates::Init,
        SessionStates::Enlist);
    GetStateMachine().AddTransition(SessionStates::Enlist,
        SessionStates::Agree);
    GetStateMachine().AddTransition(SessionStates::Agree,
        SessionStates::Registering);
    GetStateMachine().AddTransition(SessionStates::Registering,
        SessionStates::ListExchange);
    GetStateMachine().AddTransition(SessionStates::ListExchange,
        SessionStates::VerifyList);
    GetStateMachine().AddTransition(SessionStates::VerifyList,
        SessionStates::Communicating);
    GetStateMachine().AddTransition(SessionStates::Communicating,
        SessionStates::WaitingForServers);

    AddMessageParser(new Messaging::MessageParser<ServerInit>(SessionMessage::ServerInit));
    AddMessageParser(new Messaging::MessageParser<ServerEnlist>(SessionMessage::ServerEnlist));
    AddMessageParser(new Messaging::MessageParser<ServerEnlisted>(SessionMessage::ServerEnlisted));
    AddMessageParser(new Messaging::MessageParser<ServerAgree>(SessionMessage::ServerAgree));
    AddMessageParser(new Messaging::MessageParser<ClientRegister>(SessionMessage::ClientRegister));
    AddMessageParser(new Messaging::MessageParser<ServerList>(SessionMessage::ServerList));
    AddMessageParser(new Messaging::MessageParser<ServerVerifyList>(SessionMessage::ServerVerifyList));
    AddMessageParser(new Messaging::MessageParser<SessionData>(SessionMessage::SessionData));
    AddMessageParser(new Messaging::MessageParser<ServerStop>(SessionMessage::ServerStop));

    GetStateMachine().SetState(SessionStates::Offline);
    GetStateMachine().SetRestartState(SessionStates::WaitingForServers);
  }

  ServerSession::~ServerSession()
  {
  }

  void ServerSession::HandleConnection(
      const QSharedPointer<Connections::Connection> &con)
  {
    connect(con.data(), SIGNAL(Disconnected(const QString &)),
        this, SLOT(HandleDisconnectSlot()));
    GetStateMachine().HandleConnection(con->GetRemoteId());
  }
}
}
