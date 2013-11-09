#include "Session.hpp"

#include "Crypto/DiffieHellman.hpp"
#include "Crypto/DsaPrivateKey.hpp"

namespace Dissent {
namespace Session {
  Session::Session(const QSharedPointer<SessionSharedState> &shared_state) :
    m_shared_state(shared_state),
    m_sm(shared_state)
  {
  }

  Session::~Session()
  {
    GetOverlay()->GetRpcHandler()->Unregister("SessionData");
  }

  void Session::OnStart()
  {
    QList<QSharedPointer<Connections::Connection> > cons =
      GetSharedState()->GetOverlay()->GetConnectionTable().GetConnections();
    foreach(const QSharedPointer<Connections::Connection> &con, cons) {
      HandleConnection(con);
    }

    GetOverlay()->GetRpcHandler()->Register("SessionData", this, "HandleData");
    QObject::connect(m_shared_state->GetRoundAnnouncer().data(),
        SIGNAL(Announce(const QSharedPointer<Anonymity::Round> &)),
        this,
        SLOT(HandleRoundStartedSlot(const QSharedPointer<Anonymity::Round> &)));

    QObject::connect(m_shared_state->GetOverlay()->GetConnectionManager().data(),
        SIGNAL(NewConnection(const QSharedPointer<Connection> &)),
        this,
        SLOT(HandleConnectionSlot(const QSharedPointer<Connection> &)));

    GetStateMachine().StateComplete();
  }

  void Session::Send(const QByteArray &data)
  {
    GetSharedState()->AddData(data);
  }

  void Session::HandleRoundStartedSlot(const QSharedPointer<Anonymity::Round> &round)
  {
    round->SetSink(this);
    QObject::connect(round.data(), SIGNAL(Finished()),
        this, SLOT(HandleRoundFinishedSlot()));
    emit RoundStarting(round);
  }

  void Session::HandleRoundFinishedSlot()
  { 
    Anonymity::Round *round = qobject_cast<Anonymity::Round *>(sender());
    if(round != GetSharedState()->GetRound().data()) {
      qWarning() << "Received an awry Round Finished notification";
      return;
    }
  
    qDebug() << ToString() << "- round finished due to -" <<
      round->GetStoppedReason();
    
    GetSharedState()->RoundFinished(round->GetSharedPointer());

    emit RoundFinished(GetSharedState()->GetRound());
  
    if(Stopped()) {
      qDebug() << "Session stopped.";
      return;
    }

    GetStateMachine().StateComplete();
  }

  void Session::HandleData(const Messaging::Request &notification)
  {
    QByteArray packet = notification.GetData().toByteArray();
    QSharedPointer<Messaging::Message> msg = m_md.ParseMessage(packet);
    if(msg->GetMessageType() == Messaging::Message::GetBadMessageType()) {
      if(packet.size()) {
        qWarning() << "Found a message of type:" <<
          SessionMessage::MessageTypeToString(packet[0]) <<
          "but not valid for current context.";
      } else {
        qWarning() << "Found an empty message.";
      }
      return;
    }

    m_sm.ProcessData(notification.GetFrom(), msg);
  }

  void Session::HandleConnection(
      const QSharedPointer<Connections::Connection> &con)
  {
    GetStateMachine().HandleConnection(con->GetRemoteId());
  }

  void Session::HandleDisconnect(
      const QSharedPointer<Connections::Connection> &con)
  {
    GetStateMachine().HandleDisconnection(con->GetRemoteId());
  }
}
}
