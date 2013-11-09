#ifndef DISSENT_SESSION_MESSAGE_H_GUARD
#define DISSENT_SESSION_MESSAGE_H_GUARD

#include <QMetaEnum>
#include <QObject>
#include <QString>

#include "Messaging/Message.hpp"

namespace Dissent {
namespace Session {
  /**
   * Stores the names of the different Session Messages
   */
  class SessionMessage : QObject {
    Q_OBJECT
    Q_ENUMS(Names)

    public:
      enum Names {
        None = Messaging::Message::BadMessageType,
        ServerInit = 0,
        ServerEnlist,
        ServerEnlisted,
        ServerAgree,
        ServerQueued,
        ClientRegister,
        ServerList,
        ServerVerifyList,
        ServerStart,
        ServerStop,
        SessionData = 127
      };

      /** 
       * Converts a MessageType into a QString
       * @param mt value to convert
       */
      static QString MessageTypeToString(qint8 type)
      {
        int index = staticMetaObject.indexOfEnumerator("Names");
        return staticMetaObject.enumerator(index).valueToKey(type);
      }
  };
}
}

#endif
