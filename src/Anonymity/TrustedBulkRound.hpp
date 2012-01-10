#ifndef DISSENT_ANONYMITY_TRUSTED_BULK_ROUND_H_GUARD
#define DISSENT_ANONYMITY_TRUSTED_BULK_ROUND_H_GUARD

#include "Crypto/Integer.hpp"

#include "RepeatingBulkRound.hpp"

namespace Dissent {
namespace Anonymity {

  /**
   * Represents a single instance of a cryptographically secure anonymous
   * exchange.
   *
   * The "V3" bulk protocol builds on the "V2" by reusing the shuffle to
   * exchange public signing keys; however, the anonymous DiffieHellman keys
   * are no longer used.  The cleartext messages are still of the same form:
   * phase,  next phase message length, message, and signature.  The difference
   * is in how the xor texts are generated.  This model assumes that only a
   * core set of resources are trusted and allows for pregeneration of xor
   * masks.  A peer can generate sufficient bits, share them with another peer
   * who will transmit the bits for them, and then go offline.
   *
   * To generate the bits, each non-server creates a RNG for each server peer
   * using DH shared secret created as a result of combining their private DH
   * key with the servers' public DH.
   * Each server creates a RNG for each peer (server and non-server) using
   * their private DH and with each peers' public DH.  Each RNG is used
   * to generate a message spanning the length of all anonymous messages in the
   * given phase.  Each peer than combines via xor these masks to generate an
   * xor mask.  The member then xors their message into their space inside the
   * message.  This final message is distributed to all other peers.  Upon
   * collecting all messages, An xor upon all of them will reveal the original
   * messages for all peers.
   */
  class TrustedBulkRound : public RepeatingBulkRound {
    public:
      typedef Dissent::Crypto::Integer Integer;

      /**
       * Constructor
       * @param group Group used during this round
       * @param creds the local nodes credentials
       * @param round_id Unique round id (nonce)
       * @param network handles message sending
       * @param get_data requests data to share during this session
       */
      explicit TrustedBulkRound(const Group &group, const Credentials &creds,
          const Id &round_id, QSharedPointer<Network> network,
          GetDataCallback &get_data,
          CreateRound create_shuffle = &TCreateRound<ShuffleRound>);

      /**
       * If the ConnectionTable has a disconnect, the round may need to react
       * @param id the peer that was disconnected
       */
      virtual void HandleDisconnect(const Id &id);

      /**
       * This protocol supports peers in rejoining, but it isn't implemented.
       */
      virtual bool SupportsRejoins() { return false; }

    protected:
      /**
       * Does all the prep work for the next phase, clearing and zeroing out
       * all the necessary fields
       * @returns true if all good, returns false if stopped
       */
      virtual bool PrepForNextPhase();

    private:
      /**
       * Generates the entire xor message with the local members message
       * embedded within
       */
      virtual QByteArray GenerateXorMessage();

      /**
       * Prepares the random seeds
       */
      void Init();

      /**
       * The group of trusted bulk nodes (i.e., generate xor text for all)
       */
      Group _trusted_group;

      /**
       * Is in the trusted group
       */
      bool _trusted;

      QVector<Integer> _base_seeds;

      QHash<const Id, const Id> _offline_peers;
  };
}
}

#endif
