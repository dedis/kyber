#ifndef DISSENT_APPLICATIONS_NODE_H_GUARD
#define DISSENT_APPLICATIONS_NODE_H_GUARD

#include <QObject>

#include "../Anonymity/SessionManager.hpp"
#include "../Anonymity/Group.hpp"
#include "../Overlay/BasicGossip.hpp"

namespace Dissent {
namespace Anonymity {
  class Round;
  class Session;
}

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
  class Node : public QObject {
    Q_OBJECT

    public:
      typedef Dissent::Anonymity::Group Group;
      typedef Dissent::Anonymity::Round Round;
      typedef Dissent::Anonymity::Session Session;
      typedef Dissent::Anonymity::SessionManager SessionManager;
      typedef Dissent::Connections::Connection Connection;
      typedef Dissent::Connections::Id Id;
      typedef Dissent::Crypto::AsymmetricKey AsymmetricKey;
      typedef Dissent::Crypto::DiffieHellman DiffieHellman;
      typedef Dissent::Messaging::ISink ISink;
      typedef Dissent::Overlay::BasicGossip BasicGossip;
      typedef Dissent::Transports::Address Address;

      /**
       * Constructor
       * @param local_id Id for this node
       * @param local the EL addresses
       * @param remote the bootstrap peer list
       * @param group_size number of peers to wait for before creating the group
       * @param session_type type of session / round to create
       */
      Node(const Id &local_id, const QList<Address> &local,
          const QList<Address> &remote, int group_size,
          const QString &session_type);

      /**
       * Destructor
       */
      virtual ~Node();
      
      /**
       * Given the set of connected peers, generate a Group object
       */
      Group GenerateGroup();

      /**
       * Returns true once group_size is equal to peers connected to this node
       */
      bool Bootstrapped() { return _bootstrapped; }

      BasicGossip bg;
      SessionManager sm;
      const int GroupSize;
      const QString SessionType;

      QSharedPointer<AsymmetricKey> key;
      QSharedPointer<DiffieHellman> dh;
      QSharedPointer<Session> session;
      QSharedPointer<ISink> sink;

    signals:
      /**
       * Emitted when this node has created a session
       */
      void Ready();

    private slots:
      void HandleConnection(Connection *con, bool local);
      void RoundFinished(QSharedPointer<Round> round);

    private:
      bool _bootstrapped;
  };
}
}

#endif
