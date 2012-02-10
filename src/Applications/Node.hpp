#ifndef DISSENT_APPLICATIONS_BASE_NODE_H_GUARD
#define DISSENT_APPLICATIONS_BASE_NODE_H_GUARD

#include "Anonymity/SessionManager.hpp"
#include "Identity/Credentials.hpp"
#include "Identity/Group.hpp"
#include "Messaging/ISink.hpp"
#include "Overlay/BaseOverlay.hpp"
#include "Overlay/BasicGossip.hpp"
#include "Transports/Address.hpp"

namespace Dissent {
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
      typedef Dissent::Connections::Network Network;
      typedef Dissent::Messaging::ISink ISink;
      typedef Dissent::Overlay::BaseOverlay BaseOverlay;
      typedef Dissent::Overlay::BasicGossip BasicGossip;
      typedef Dissent::Transports::Address Address;

      /**
       * Constructor
       * @param local the EL addresses
       * @param remote the bootstrap peer list
       */
      explicit Node(const Credentials &creds,
          const Group &group,
          const QList<Address> &local,
          const QList<Address> &remote,
          const QSharedPointer<ISink> &sink,
          const QString &type);

      /**
       * Destructor
       */
      virtual ~Node();

      Credentials GetCredentials() const { return _creds; }
      Group GetGroup() const { return _group; }
      QSharedPointer<Network> GetNetwork() { return _net; }
      QSharedPointer<BaseOverlay> GetOverlay() { return _overlay; }
      SessionManager &GetSessionManager() { return _sm; }
      QSharedPointer<ISink> GetSink() const { return _sink; }

    private:
      Credentials _creds;
      Group _group;
      QSharedPointer<BaseOverlay> _overlay;
      QSharedPointer<Network> _net;
      SessionManager _sm;
      QSharedPointer<ISink> _sink;
  };
}
}

#endif
