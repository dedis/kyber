#ifndef DISSENT_APPLICATIONS_SESSION_FACTORY_H_GUARD
#define DISSENT_APPLICATIONS_SESSION_FACTORY_H_GUARD

#include <QHash>

#include "../Anonymity/Group.hpp"
#include "../Anonymity/Round.hpp"
#include "../Connections/Id.hpp"

#include "Node.hpp"

namespace Dissent {
namespace Applications {
  /**
   * Generates an appropriate session given the input
   */
  class SessionFactory {
    public:
      typedef Dissent::Anonymity::CreateRound CreateRound;
      typedef Dissent::Anonymity::Group Group;
      typedef Dissent::Connections::Id Id;
      typedef void (*Callback)(Node *, const Id &, const Group &);

      /**
       * Singleton implemention
       */
      static SessionFactory &GetInstance();

      /**
       * Register a callback for the specific type
       * @param type the type for the callback
       * @param cb the "constructor" for the type
       */
      void AddCreateCallback(const QString &type, Callback cb);

      /**
       * Adds the session expressed by type to the node
       * @param node the node to add the session to
       * @param type the type of session to create
       */
      void Create(Node *node, const Id &session_id, const Group &group,
          const QString &type) const;

      /**
       * Create a SecureSession / ShuffleRound
       */
      static void CreateShuffleRoundSession(Node *node, const Id &session_id,
          const Group &group);

      /**
       * Create a Session / NullRound
       */
      static void CreateNullRoundSession(Node *node, const Id &session_id,
          const Group &group);

      /**
       * Create a Bulk "V1"
       */
      static void CreateBulkRoundSession(Node *node, const Id &session_id,
          const Group &group);

      /**
       * Create a Bulk "V2"
       */
      static void CreateRepeatingBulkRoundSession(Node *node,
          const Id &session_id, const Group &group);

      /**
       * Create a Bulk "V3"
       */
      static void CreateTrustedBulkRoundSession(Node *node,
          const Id &session_id, const Group &group);

    private:
      static void Common(Node *node, const Id &session_id, CreateRound cr,
          const Group &group);

      /**
       * No inheritance, this is a singleton object
       */
      explicit SessionFactory(); 

      /**
       * No copying of singleton objects
       */
      Q_DISABLE_COPY(SessionFactory)

      QHash<QString, Callback> _type_to_create;
  };
}
}

#endif
