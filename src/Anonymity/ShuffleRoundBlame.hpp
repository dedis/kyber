#ifndef DISSENT_ANONYMITY_SHUFFLE_ROUND_BLAME_H_GUARD
#define DISSENT_ANONYMITY_SHUFFLE_ROUND_BLAME_H_GUARD

#include "ShuffleRound.hpp"

#include <QBitArray>
#include <QDataStream>
#include <QMetaEnum>

#include "../Crypto/CryptoFactory.hpp"

namespace Dissent {
namespace Anonymity {
  class ShuffleRoundBlame : public ShuffleRound {
    public:
      /**
       * Constructor
       * @param group_gen Generate groups for use during this round
       * @param local_id The local peers id
       * @param round_id Unique round id (nonce)
       * @param outer_key the peers private outer key
       */
      ShuffleRoundBlame(QSharedPointer<GroupGenerator> group_gen,
          const Id &local_id, const Id &round_id, AsymmetricKey *outer_key);

      /**
       * Destructor
       */
      virtual ~ShuffleRoundBlame() {}

      /**
       * Returns the nodes list of inner public keys
       */
      inline const QVector<AsymmetricKey *> &GetPublicInnerKeys() { return _public_inner_keys; }

      /**
       * Returns the nodes list of outer public keys
       */
      inline const QVector<AsymmetricKey *> &GetPublicOuterKeys() { return _public_outer_keys; }

      /**
       * Returns the nodes outer public key
       */
      inline const AsymmetricKey *GetPrivateOuterKey() { return _outer_key.data(); }

      /**
       * Returns the nodes inputted shuffle cipher text
       */
      inline const QVector<QByteArray> &GetShuffleCipherText() { return _shuffle_ciphertext; }

      /**
       * Returns the ndoes outputted shuffle cipher text
       */
      inline const QVector<QByteArray> &GetShuffleClearText() { return _shuffle_cleartext; }

      /**
       * Returns the inner encrypted only data
       */
      inline const QVector<QByteArray> &GetEncryptedData() { return _encrypted_data; }

      /**
       * Returns 1, 0, -1, if the given index is go, no message, or no for the
       * go / no go phase
       * @param idx the peer to inquire about
       */
      int GetGo(int idx);

      virtual bool Start();

      inline virtual void ProcessData(const QByteArray &data, const Id &from)
      {
        ShuffleRound::ProcessData(data, from);
      }

    protected:
      virtual inline void Broadcast(const QByteArray &) {}
      virtual inline void Send(const QByteArray &, const Id &) {}

      virtual void GenerateShufflerGroup()
      {
        SetShufflers(GetGroupGenerator()->CurrentGroup());
      }
      virtual void BroadcastPublicKeys();
      virtual void SubmitData();
      virtual void Shuffle();
      virtual void Verify();
      virtual void StartBlame();
      virtual void BroadcastPrivateKey();
      virtual void Decrypt();
      virtual void BlameRound();

    private:
      /**
       * Empty CT for this round since it won't be used
       */
      static const ConnectionTable _empty_ct;

      /**
       * Empty Rpc for this round since it won't be used
       */
      static RpcHandler _empty_rpc;

      static EmptyGetDataCallback _empty_get_data;
  };
}
}

#endif
