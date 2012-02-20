#ifndef DISSENT_APPLICATIONS_BASE_NODE_H_GUARD
#define DISSENT_APPLICATIONS_BASE_NODE_H_GUARD

#include "Anonymity/SessionManager.hpp"
#include "Identity/Credentials.hpp"
#include "Identity/Group.hpp"
#include "Identity/GroupHolder.hpp"
#include "Messaging/ISink.hpp"
#include "Overlay/BaseOverlay.hpp"
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
      typedef Dissent::Identity::GroupHolder GroupHolder;
      typedef Dissent::Anonymity::SessionManager SessionManager;
      typedef Dissent::Connections::Connection Connection;
      typedef Dissent::Connections::Network Network;
      typedef Dissent::Messaging::ISink ISink;
      typedef Dissent::Overlay::BaseOverlay BaseOverlay;
      typedef Dissent::Transports::Address Address;

      static QSharedPointer<Node> CreateBasicGossip(const Credentials &creds,
          const Group &group, const QList<Address> &local,
          const QList<Address> &remote, const QSharedPointer<ISink> &sink,
          const QString &session);

      static QSharedPointer<Node> CreateClientServer(const Credentials &creds,
          const Group &group, const QList<Address> &local,
          const QList<Address> &remote, const QSharedPointer<ISink> &sink,
          const QString &session);

      /**
       * Constructor
       * @param local the EL addresses
       * @param remote the bootstrap peer list
       */
      explicit Node(const Credentials &creds,
          const QSharedPointer<GroupHolder> &group_holder,
          const QSharedPointer<BaseOverlay> &overlay,
          const QSharedPointer<ISink> &sink,
          const QString &type);

      /**
       * Destructor
       */
      virtual ~Node();

      Credentials GetCredentials() const { return _creds; }
      QSharedPointer<GroupHolder> GetGroupHolder() const { return _group_holder; }
      Group GetGroup() const { return _group_holder->GetGroup(); }
      QSharedPointer<Network> GetNetwork() { return _net; }
      QSharedPointer<BaseOverlay> GetOverlay() { return _overlay; }
      SessionManager &GetSessionManager() { return _sm; }
      QSharedPointer<ISink> GetSink() const { return _sink; }

    private:
      Credentials _creds;
      QSharedPointer<GroupHolder> _group_holder;
      QSharedPointer<BaseOverlay> _overlay;
      QSharedPointer<Network> _net;
      SessionManager _sm;
      QSharedPointer<ISink> _sink;
  };
}
}

#endif
