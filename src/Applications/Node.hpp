#ifndef DISSENT_APPLICATIONS_NODE_H_GUARD
#define DISSENT_APPLICATIONS_NODE_H_GUARD

#include "Identity/Credentials.hpp"
#include "Identity/Group.hpp"
#include "Anonymity/SessionManager.hpp"
#include "Overlay/BasicGossip.hpp"

namespace Dissent {
namespace Crypto {
  class AsymmetricKey;
  class DiffieHellman;
}

namespace Messaging {
  class ISink;
}

namespace Applications {
  /**
   * A wrapper class combining an overlay, session manager, session, sink,
   * key, and whatever else might be necessary.
   */
  class Node {
    public:
      typedef Dissent::Identity::Credentials Credentials;
      typedef Dissent::Identity::Group Group;
      typedef Dissent::Anonymity::SessionManager SessionManager;
      typedef Dissent::Connections::Connection Connection;
      typedef Dissent::Messaging::ISink ISink;
      typedef Dissent::Overlay::BasicGossip BasicGossip;
      typedef Dissent::Transports::Address Address;

      /**
       * Constructor
       * @param local the EL addresses
       * @param remote the bootstrap peer list
       */
      explicit Node(const Credentials &creds, const QList<Address> &local,
          const QList<Address> &remote, const Group &group, const QString &type,
          const QSharedPointer<ISink> &sink = QSharedPointer<ISink>());

      /**
       * Destructor
       */
      virtual ~Node();

      /**
       * Hack to start session after sink has been set.
       */
      void StartSession();
      
      Credentials creds;
      BasicGossip bg;
      SessionManager sm;
      Group base_group;
      QString SessionType;
      QSharedPointer<ISink> sink;
  };
}
}

#endif
