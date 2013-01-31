#ifndef DISSENT_CRYPTO_BLOGDROP_PLAINTEXT_H_GUARD
#define DISSENT_CRYPTO_BLOGDROP_PLAINTEXT_H_GUARD

#include <QByteArray>
#include <QSharedPointer>
#include "Crypto/AbstractGroup/Element.hpp"
#include "Parameters.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  /**
   * Object holding BlogDrop encoded plaintext
   */
  class Plaintext {

    public:

      typedef Dissent::Crypto::AbstractGroup::Element Element;

      /** * Constructor
       */
      Plaintext(const QSharedPointer<const Parameters> params);

      /**
       * Destructor
       */
      virtual ~Plaintext() {}

      /**
       * Encode ByteArray into BlogDrop plaintext
       * @param input QByteArray to encode
       */
      void Encode(const QByteArray &input); 

      /**
       * Decode a plaintext element into a QByteArray
       * @param ret reference in which to return string
       * @returns true if everything is okay, false if cannot read
       *          string
       */
      bool Decode(QByteArray &ret) const;

      /**
       * Set plaintext to random value
       */
      void SetRandom();

      /**
       * Return integer representing this plaintext
       */
      inline QList<Element> GetElements() const { return _ms; }

      /**
       * Number of bytes that can fit in a plaintext
       */
      inline static int CanFit(const QSharedPointer<const Parameters> params) {
        return (params->GetNElements() * params->GetMessageGroup()->BytesPerElement());
      }

      /**
       * Reveal a plaintext by combining ciphertext elements
       */
      void Reveal(const QList<Element> &c);

    private:

      const QSharedPointer<const Parameters> _params;
      QList<Element> _ms;

  };

}
}
}

#endif
