#ifndef DISSENT_ANONYMITY_SHUFFLE_ROUND_BLAME_H_GUARD
#define DISSENT_ANONYMITY_SHUFFLE_ROUND_BLAME_H_GUARD

#include <QBitArray>
#include <QDataStream>
#include <QMetaEnum>

#include "ShuffleRound.hpp"

namespace Dissent {
namespace Anonymity {
  class ShuffleRoundBlame : public ShuffleRound {
    public:
      /**
       * Constructor
       * @param group Group used during this round
       * @param local_id The local peers id
       * @param round_id Unique round id (nonce)
       * @param outer_key the peers private outer key
       */
      explicit ShuffleRoundBlame(const Group &group, const Id &local_id,
          const Id &round_id, const QSharedPointer<AsymmetricKey> &outer_key);

      /**
       * Destructor
       */
      virtual ~ShuffleRoundBlame() {}

      /**
       * Returns the nodes list of inner public keys
       */
      inline QVector<QSharedPointer<AsymmetricKey> > GetPublicInnerKeys()
      {
        return _state->public_inner_keys;
      }

      /**
       * Returns the nodes list of outer public keys
       */
      inline QVector<QSharedPointer<AsymmetricKey> > &GetPublicOuterKeys()
      {
        return _state->public_outer_keys;
      }

      /**
       * Returns the nodes outer private key
       */
      inline QSharedPointer<AsymmetricKey> GetPrivateOuterKey() const
      {
        return _server_state->outer_key;
      }

      /**
       * Returns the nodes inputted shuffle cipher text
       */
      inline QVector<QByteArray> GetShuffleCipherText() const
      {
        return _server_state->shuffle_input;
      }

      /**
       * Returns the ndoes outputted shuffle cipher text
       */
      inline QVector<QByteArray> GetShuffleClearText() const
      {
        return _server_state->shuffle_output;
      }

      /**
       * Returns the inner encrypted only data
       */
      inline QVector<QByteArray> GetEncryptedData() const
      {
        return _state->encrypted_data;
      }

      /**
       * Returns 1, 0, -1, if the given index is go, no message, or no for the
       * go / no go phase
       * @param idx the peer to inquire about
       */
      int GetGo(int idx);

      inline virtual void ProcessData(const Id &from, const QByteArray &data)
      {
        ShuffleRound::ProcessData(from, data);
      }

    protected:
      virtual inline void VerifiableBroadcast(const QByteArray &) {}
      virtual inline void VerifiableSend(const QByteArray &, const Id &) {}

      virtual void BroadcastPublicKeys();
      virtual void GenerateCiphertext();
      virtual void SubmitCiphertext();
      virtual void Shuffle();
      virtual void VerifyInnerCiphertext();
      virtual void BroadcastPrivateKey();
      virtual void StartBlame();
      virtual void HandleBlame(const Id &id, QDataStream &stream);
  };
}
}

#endif
