#ifndef DISSENT_CRYPTO_BLOGDROP_XOR_SERVER_CIPHERTEXT_H_GUARD
#define DISSENT_CRYPTO_BLOGDROP_XOR_SERVER_CIPHERTEXT_H_GUARD

#include "Crypto/AbstractGroup/ByteElementData.hpp"

#include "ServerCiphertext.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  class XorServerCiphertext : public ServerCiphertext {

    public:

      typedef Crypto::AbstractGroup::ByteElementData ByteElementData;

      /**
       * Constructor: Initialize a ciphertext
       * @param params Group parameters
       * @param author_pub Author public key
       * @param client_pks Client public keys for ciphertexts
       */
      XorServerCiphertext(const QSharedPointer<const Parameters> params, 
          const QSharedPointer<const PublicKey> author_pub,
          const QSharedPointer<const PublicKeySet> client_pks) :
        ServerCiphertext(params, author_pub, params->GetNElements()) 
      {
        Library &lib = CryptoFactory::GetInstance().GetLibrary();

        for(int client_idx=0; client_idx<client_pks->GetNKeys(); client_idx++) {
          for(int elm_idx=0; elm_idx<_params->GetNElements(); elm_idx++) {
            QByteArray seed = QString("elm:%2,author:").arg(
                elm_idx).toAscii() + author_pub->GetByteArray();

            QScopedPointer<Utils::Random> rng(lib.GetRandomNumberGenerator(seed));

            QByteArray block(_params->GetMessageGroup()->GetSecurityParameter()/8, 0);
            rng->GenerateBlock(block);

            Element e = Element(new ByteElementData(block));
            _elements.append(_params->GetMessageGroup()->Multiply(
                _params->GetMessageGroup()->GetIdentity(), e));
          }
        }
      }

      /**
       * Constructor: Initialize a ciphertext from serialized version
       * @param params Group parameters
       * @param author_pub Author public key
       * @param client_pks Client public keys
       * @param serialized serialized byte array
       */
      XorServerCiphertext(const QSharedPointer<const Parameters> params, 
          const QSharedPointer<const PublicKey> author_pub,
          const QSharedPointer<const PublicKeySet> /*client_pks*/,
          const QByteArray &serialized) :
        ServerCiphertext(params, author_pub, params->GetNElements()) 
      {
        QDataStream stream(serialized);

        for(int i=0; i<_params->GetNElements(); i++) {
          QByteArray tmp;
          stream >> tmp;
          _elements.append(_params->GetMessageGroup()->ElementFromByteArray(tmp));
        }
      }

      /**
       * Destructor
       */
      virtual ~XorServerCiphertext() {}

      /**
       * Initialize elements proving correctness of ciphertext
       * @param phase transmisssion round/phase index
       * @param Server private key used to generate proof
       */
      inline virtual void SetProof(int /*phase*/, const QSharedPointer<const PrivateKey> /*priv*/) {};

      /**
       * Check ciphertext proof
       * @param pub public key of server
       * @param phase transmisssion round/phase index
       * @returns true if proof is okay
       */
      inline virtual bool VerifyProof(int /*phase*/, const QSharedPointer<const PublicKey> /*pub*/) const 
      {
        return true;
      }

      /**
       * Get serialized version
       */
      inline virtual QByteArray GetByteArray() const
      {
        QByteArray out;
        QDataStream stream(&out, QIODevice::WriteOnly);

        for(int i=0; i<_params->GetNElements(); i++) {
          stream << _params->GetMessageGroup()->ElementToByteArray(_elements[i]);
        }

        return out;
      }

    private:

  };
}
}
}

#endif
