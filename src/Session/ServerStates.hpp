#ifndef DISSENT_SESSION_SERVER_COMM_STATE_H_GUARD
#define DISSENT_SESSION_SERVER_COMM_STATE_H_GUARD

#include <QDebug>

#include "Connections/IOverlaySender.hpp"
#include "Messaging/ISender.hpp"
#include "Messaging/State.hpp"
#include "Utils/QRunTimeError.hpp"

#include "SessionData.hpp"
#include "SessionMessage.hpp"
#include "SessionSharedState.hpp"
#include "SessionState.hpp"

namespace Dissent {
namespace Session {
  class ServerCommState : public SessionState {
    public:
      explicit ServerCommState(
          const QSharedPointer<Messaging::StateData> &data) :
        SessionState(data,
            SessionStates::Communicating,
            SessionMessage::SessionData)
      {
      }

      virtual Messaging::State::ProcessResult ProcessPacket(
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
        return Messaging::State::NoChange;
      }

    private:
      virtual bool StorePacket(const QSharedPointer<Messaging::Message> &msg) const
      {
        // Verify this is a valid packet
        return (msg->GetMessageType() == SessionMessage::ServerInit);
      }
  };
}
}

#endif
