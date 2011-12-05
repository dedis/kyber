#ifndef DISSENT_ANONYMITY_TRUSTED_BULK_ROUND_H_GUARD
#define DISSENT_ANONYMITY_TRUSTED_BULK_ROUND_H_GUARD

#include "RepeatingBulkRound.hpp"

namespace Dissent {
namespace Anonymity {
  /**
   * Represents a single instance of a cryptographically secure anonymous
   * exchange.
   *
   * The "V3" bulk protocol builds on the "V2" by reusing the shuffle to
   * exchange anonymous DiffieHellman public components and public signing
   * keys.  The cleartext messages are still of the same form: phase,  next
   * phase message length, message, and signature.  The difference is in how
   * the xor texts are generated.  This model assumes that only a core set
   * of resources are trusted and allows for pregeneration of xor masks.  A
   * peer can generate sufficient bits, share them with another peer who will
   * transmit the bits for them, and then go offline.
   *
   * To generate the bits, creates a RNG for each trusted peer using DH shared
   * secret created as a result of combining the anonymous private DH with the
   * public trusted DH.  In addition, each trusted DH creates a RNG for each
   * peer using their private DH and the anonymous public DH.  Each RNG is used
   * to generate a message spanning the length of all anonymous messages in the
   * given phase.  Each peer than combines via xor these masks to generate an
   * xor mask.  The member then xors their message into their space inside the
   * message.  This final message is the one distributed to all other peers.  A
   * peer collecting all messages can xor them together to reveal all the
   * original messages.
   */
  class TrustedBulkRound : public RepeatingBulkRound {
    public:
      TrustedBulkRound(QSharedPointer<GroupGenerator> group_gen,
          const Credentials &creds, const Id &round_id, QSharedPointer<Network> network,
          GetDataCallback &get_data,
          CreateRound create_shuffle = &TCreateRound<ShuffleRound>);

      /**
       * Start the bulk round
       */
      virtual bool Start();

    private:
      /**
       * Generates the entire xor message with the local members message
       * embedded within
       */
      virtual QByteArray GenerateXorMessage();

      /**
       * The group of trusted bulk nodes (i.e., generate xor text for all)
       */
      Group _trusted_group;

      /**
       * Is in the trusted group
       */
      bool _trusted;
  };
}
}

#endif
