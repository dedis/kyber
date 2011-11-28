#ifndef DISSENT_APPLICATIONS_SESSION_FACTORY_H_GUARD
#define DISSENT_APPLICATIONS_SESSION_FACTORY_H_GUARD

#include <QHash>

#include "../Anonymity/Group.hpp"
#include "../Anonymity/Round.hpp"

#include "Node.hpp"

namespace Dissent {
namespace Applications {
  /**
   * Generates an appropriate session given the input
   */
  class SessionFactory {
    public:
      typedef void (*Callback)(Node *);
      typedef Dissent::Anonymity::CreateRound CreateRound;
      typedef Dissent::Anonymity::CreateGroupGenerator CreateGroupGenerator;

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
      void Create(Node *node, const QString &type) const;

      /**
       * Create a SecureSession / ShuffleRound
       */
      static void CreateShuffleRoundSession(Node *node);

      /**
       * Create a SecureSession / FastShuffleRound
       */
      static void CreateFastShuffleRoundSession(Node *node);

      /**
       * Create a Session / NullRound
       */
      static void CreateNullRoundSession(Node *node);

    private:
      static void Common(Node *node, CreateRound cr, CreateGroupGenerator cgg);

      /**
       * No inheritance, this is a singleton object
       */
      SessionFactory(); 

      /**
       * No copying of singleton objects
       */
      Q_DISABLE_COPY(SessionFactory)

      QHash<QString, Callback> _type_to_create;
  };
}
}

#endif
