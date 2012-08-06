#ifndef DISSENT_APPLICATIONS_SESSION_FACTORY_H_GUARD
#define DISSENT_APPLICATIONS_SESSION_FACTORY_H_GUARD

#include <QHash>

#include "Anonymity/Round.hpp"
#include "Connections/Id.hpp"
#include "Crypto/KeyShare.hpp"

#include "AuthFactory.hpp"

namespace Dissent {
namespace Applications {
  class Node;

  /**
   * Generates an appropriate session given the input
   */
  class SessionFactory {
    public:
      typedef Anonymity::CreateRound CreateRound;
      typedef Connections::Id Id;
      typedef Crypto::KeyShare KeyShare;

      static const char* SessionNames(int id)
      {
        static const char* sessions[] = {
          "null",
          "shuffle",
          "bulk",
          "repeatingbulk",
          "csbulk",
          "tolerantbulk",
        };
        return sessions[id];
      }

      enum SessionType {
        INVALID = -1,
        NULL_ROUND = 0,
        SHUFFLE,
        BULK,
        REPEATING_BULK,
        CSBULK,
        TOLERANT_BULK,
      };

      static SessionType GetSessionType(const QString &stype)
      {
        static QHash<QString, SessionType> string_to_type = BuildStringToTypeHash();
        return string_to_type.value(stype, INVALID);
      }

      static void CreateSession(Node *node, const Id &session_id,
          SessionType type, AuthFactory::AuthType auth_type,
          const QSharedPointer<KeyShare> &public_keys);

    private:
      static QHash<QString, SessionType> BuildStringToTypeHash()
      {
        QHash<QString, SessionType> hash;
        for(int idx = NULL_ROUND; idx <= TOLERANT_BULK; idx++) {
          hash[SessionNames(idx)] = static_cast<SessionType>(idx);
        }
        return hash;
      }

      Q_DISABLE_COPY(SessionFactory)
  };
}
}

#endif
