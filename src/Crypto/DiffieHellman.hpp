#ifndef DISSENT_CRYPTO_DIFFIE_HELLMAN_KEY_H_GUARD
#define DISSENT_CRYPTO_DIFFIE_HELLMAN_KEY_H_GUARD

#include <QDebug>
#include <QByteArray>
#include <QString>

namespace Dissent {
namespace Crypto {
  /**
   * Stores a Diffie-Hellman exchange -- shared secret exchanged in plaintext
   */
  class DiffieHellman {
    public:
      static QByteArray GetP()
      {
        if(_p.isEmpty()) {
          Init();
        }
        return _p;
      }

      static QByteArray GetG()
      {
        if(_g.isEmpty()) {
          Init();
        }
        return _g;
      }

      static QByteArray GetQ()
      {
        if(_q.isEmpty()) {
          Init();
        }
        return _q;
      }

      /**
       * Destructor
       */
      virtual ~DiffieHellman() {}

      /**
       * Retrieves the public component of the Diffie-Hellman agreement
       */
      virtual QByteArray GetPublicComponent() const = 0;

      /**
       * Retrieves the private component of the Diffie-Hellman agreement
       */
      virtual QByteArray GetPrivateComponent() const = 0;

      /**
       * Return the shared secret given the other sides public component
       * @param remote_pub the other sides public component
       */
      virtual QByteArray GetSharedSecret(const QByteArray &remote_pub) const = 0;

    private:
      static void Init();
      static QByteArray _p, _g, _q;
  };
}
}

#endif
