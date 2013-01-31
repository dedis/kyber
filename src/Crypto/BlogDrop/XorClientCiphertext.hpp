#ifndef DISSENT_CRYPTO_BLOGDROP_XOR_CLIENT_CIPHERTEXT_H_GUARD
#define DISSENT_CRYPTO_BLOGDROP_XOR_CLIENT_CIPHERTEXT_H_GUARD

#include "Utils/Random.hpp"

#include "Crypto/AbstractGroup/ByteElementData.hpp"
#include "ClientCiphertext.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  /**
   * XOR-ing DC-net style client ciphertext. This is not 
   * verifiable -- we're only using it for evaluation.
   */
  class XorClientCiphertext : public ClientCiphertext {

    public:

      typedef Dissent::Crypto::AbstractGroup::ByteElementData ByteElementData;
      typedef Dissent::Crypto::AbstractGroup::Element Element;

      /**
       * Constructor: Initialize a ciphertext with a fresh
       * one-time public key
       * @param params Group parameters
       * @param server_pks Server public keys
       * @param author_pub author public key
       * @param n_elms number of group elements in each ciphertext
       */
      explicit XorClientCiphertext(const QSharedPointer<const Parameters> params, 
          const QSharedPointer<const PublicKeySet> server_pks,
          const QSharedPointer<const PublicKey> author_pub) :
        ClientCiphertext(params, server_pks, author_pub, params->GetNElements()) 
      {
        Library &lib = CryptoFactory::GetInstance().GetLibrary();

        for(int server_idx=0; server_idx<server_pks->GetNKeys(); server_idx++) {
          for(int elm_idx=0; elm_idx<_params->GetNElements(); elm_idx++) {
            QByteArray seed = QString("elm:%2,author:").arg(elm_idx).toAscii() + author_pub->GetByteArray();

            QScopedPointer<Utils::Random> rng(lib.GetRandomNumberGenerator(seed));

            QByteArray block(_params->GetMessageGroup()->GetSecurityParameter()/8, 0);
            rng->GenerateBlock(block);

            Element e = Element(new ByteElementData(block));
            _elements.append(_params->GetMessageGroup()->Multiply(
                _params->GetMessageGroup()->GetIdentity(), e));
          }
        //  qDebug() << "Xoring for server" << server_idx;
        }
      }

      /**
       * Constructor: Initialize a ciphertext from a serialized bytearray
       * @param params Group parameters
       * @param server_pks Server public keys
       * @param author_pub author public key
       * @param the byte array
       */
      explicit XorClientCiphertext(const QSharedPointer<const Parameters> params, 
          const QSharedPointer<const PublicKeySet> server_pks,
          const QSharedPointer<const PublicKey> author_pub, 
          const QByteArray &serialized) :
        ClientCiphertext(params, server_pks, author_pub, params->GetNElements()) 
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
      virtual ~XorClientCiphertext() {}

      /**
       * Initialize elements proving correctness of ciphertext
       * @param transmission round/phase index
       * @param client_priv client private key used to generate proof
       * @param author_priv author private key used to generate proof
       * @param m author's plaintext message
       */
      virtual inline void SetAuthorProof(int /*phase*/, 
          const QSharedPointer<const PrivateKey> /*client_priv*/, 
          const QSharedPointer<const PrivateKey> /*author_priv*/, 
          const Plaintext &m) 
      {
        QList<Element> es = m.GetElements();
        for(int i=0; i<es.count(); i++) {
          _elements[i] = _params->GetMessageGroup()->Multiply(_elements[i], es[i]);
        }
      }

      /**
       * Initialize elements proving correctness of ciphertext
       * @param phase the message transmission phase/round index
       * @param client_priv client private key used to generate proof
       */
      virtual inline void SetProof(int /*phase*/, const QSharedPointer<const PrivateKey> /*client_priv*/) 
      {}

      /**
       * Check ciphertext proof
       * @param transmission round/phase index
       * @param client (NOT author) private key
       * @returns true if proof is okay
       */
      virtual inline bool VerifyProof(int /*phase*/, const QSharedPointer<const PublicKey> /*client_pub*/) const 
      {
        return true;
      }

      /**
       * Get a byte array for this ciphertext
       */
      virtual inline QByteArray GetByteArray() const 
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
