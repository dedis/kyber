#ifndef DISSENT_APPLICATIONS_NODE_H_GUARD
#define DISSENT_APPLICATIONS_NODE_H_GUARD

#include <QObject>

#include "../Overlay/BasicGossip.hpp"
#include "../Anonymity/SessionManager.hpp"
#include "../Crypto/AsymmetricKey.hpp"

using namespace Dissent::Anonymity;
using namespace Dissent::Connections;
using namespace Dissent::Crypto;
using namespace Dissent::Overlay;
using namespace Dissent::Messaging;

namespace Dissent {
namespace Applications {
  /**
   * A wrapper class combining an overlay, session manager, session, sink,
   * key, and whatever else might be necessary.
   */
  class Node : public QObject {
    Q_OBJECT

    public:
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
