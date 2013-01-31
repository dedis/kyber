#ifndef DISSENT_CRYPTO_BLOGDROP_PRIVATEKEY_H_GUARD
#define DISSENT_CRYPTO_BLOGDROP_PRIVATEKEY_H_GUARD

#include "Crypto/Integer.hpp"
#include "Parameters.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  /**
   * Object holding BlogDrop private key
   */
  class PrivateKey {

    public:

      /**
       * Constructor: Initialize a random private key
       */
      PrivateKey(const QSharedPointer<const Parameters> params);

      /**
       * Constructor: Initialize a private key from an integer
       */
      PrivateKey(const QSharedPointer<const Parameters> params, const Integer key);

      /**
       * Destructor
       */
      virtual ~PrivateKey();

      /**
       * Return integer exponent
       */
      inline const Integer &GetInteger() const { return _key; }

      /**
       * Return parameters used
       */
      inline const QSharedPointer<const Parameters> GetParameters() const { return _params; }

    private:

      QSharedPointer<const Parameters> _params;
      Integer _key;

  };
}
}
}

#endif
