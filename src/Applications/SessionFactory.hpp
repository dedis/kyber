#ifndef DISSENT_APPLICATIONS_SESSION_FACTORY_H_GUARD
#define DISSENT_APPLICATIONS_SESSION_FACTORY_H_GUARD

#include <QHash>

#include "Node.hpp"

namespace Dissent {
namespace Applications {
  /**
   * Generates an appropriate session given the input
   */
  class SessionFactory {
    public:
      typedef void (*Callback)(Node *);

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
      void Create(Node *node, const QString &type);

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
      static void Common(Node *node, Session *session);
      SessionFactory();
      QHash<QString, Callback> _type_to_create;
  };
}
}

#endif
