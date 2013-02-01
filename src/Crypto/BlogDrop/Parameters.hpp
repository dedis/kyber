#ifndef DISSENT_CRYPTO_BLOGDROP_PARAMETERS_H_GUARD
#define DISSENT_CRYPTO_BLOGDROP_PARAMETERS_H_GUARD

#include <QByteArray>
#include <QSharedPointer>

#include "Crypto/AbstractGroup/AbstractGroup.hpp"

namespace Dissent {
  namespace Crypto {
    namespace BlogDrop {

      /**
       * Object holding group definition
       */
      class Parameters {

        public:

          typedef Dissent::Crypto::AbstractGroup::AbstractGroup AbstractGroup;
          typedef Dissent::Crypto::AbstractGroup::Element Element;

          typedef enum {
            ProofType_ElGamal = 0,
            ProofType_HashingGenerator, 
            ProofType_Invalid
          } ProofType;


          /**
           * Constructor that uses 512-bit integer group (for testing)
           */
          static QSharedPointer<Parameters> IntegerElGamalTesting();

          /**
           * Constructor that uses 1024-bit fixed integer group 
           */
          static QSharedPointer<Parameters> IntegerElGamalProduction(
              const QByteArray &round_nonce = QByteArray());

          /**
           * Constructor that uses 512-bit integer group (for testing)
           */
          static QSharedPointer<Parameters> IntegerHashingTesting();

          /**
           * Constructor that uses 1024-bit fixed integer group 
           */
          static QSharedPointer<Parameters> IntegerHashingProduction(const QByteArray &round_nonce = QByteArray());

          /**
           * Constructor that uses 256-bit fixed EC group 
           * (Supposedly 256-bit ECs are equivalent to 3072-bit 
           * RSA/DH groups) implemented with Crypto++
           */
          static QSharedPointer<Parameters> CppECElGamalProduction(const QByteArray &round_nonce = QByteArray());

          /**
           * Constructor that uses 256-bit fixed EC group 
           * (Supposedly 256-bit ECs are equivalent to 3072-bit 
           * RSA/DH groups) implemented with Crypto++
           */
          static QSharedPointer<Parameters> CppECHashingProduction(const QByteArray &round_nonce = QByteArray());

          /**
           * Constructor that has empty/invalid parameters
           */
          static QSharedPointer<Parameters> Empty();

          /**
           * Destructor
           */
          virtual ~Parameters() {}

          /**
           * Copy constructor
           */
          Parameters(const Parameters &p);

          /**
           * Get the group that contains the public key elements 
           */
          inline QSharedPointer<const AbstractGroup> GetKeyGroup() const { return _key_group; }

          /**
           * Get the group that contains the ciphertext and message elements
           */
          inline QSharedPointer<const AbstractGroup> GetMessageGroup() const { 
            return _msg_group;
          }

          /**
           * Get a serialized version of these parameters
           */
          QByteArray GetByteArray() const;

          /**
           * Get type of proof being used
           */
          inline ProofType GetProofType() const { return _proof_type; }

          inline QByteArray GetRoundNonce() const { return _round_nonce; }
          virtual inline void SetNElements(int new_n) { _n_elements = new_n; }
          virtual inline void SetRoundNonce(QByteArray nonce) { _round_nonce = nonce; }
          virtual inline int GetNElements() const { return _n_elements; }

          inline Integer GetGroupOrder() const { 
            // For proofs to work, the two groups must have the same order
            Q_ASSERT(_key_group->GetOrder() == _msg_group->GetOrder());
            return _key_group->GetOrder();
          }

          /**
           * Constructor: it's better to use one of the static constructors
           * @param proof_type which proof construction to use
           * @param round_nonce unique ID for this session
           * @param key_group group in which pub/priv keys are picked
           * @param msg_group group in which message and ciphertexts are picked
           * @param n_elements number of group elements per ciphertext blob
           */
          Parameters(ProofType proof_type, 
              const QByteArray &round_nonce, 
              const QSharedPointer<const AbstractGroup> &key_group, 
              const QSharedPointer<const AbstractGroup> &msg_group, 
              int n_elements);

          /**
           * Convert a ProofType to string
           */
          static QString ProofTypeToString(ProofType pt);

          /**
           * Get a printable description of the Parameters
           */
          QString ToString() const;

    private:

      Parameters();

      /**
       * Proof technique being used
       */
      const ProofType _proof_type;

      /**
       * This string must be different in every run of the protocol to 
       * prevent replay attacks
       */
      QByteArray _round_nonce;

      /**
       * The group containing the public keys
       */
      QSharedPointer<const AbstractGroup> _key_group;

      /**
       * The group containing the message elements (plaintexts + ciphertexts)
       */
      QSharedPointer<const AbstractGroup> _msg_group;

      /**
       * Number of ciphertext elements in a single ciphertext
       */
      int _n_elements;
  };
}
}
}

#endif
