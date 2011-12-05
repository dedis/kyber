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
   * of resources are trusted allowing the non-trusted peers to be offline
   * during transmissions so long as they have generated sufficient bits.
   * In short, all members start with an xor mask by combining their anonymous
   * DH with the trusted members well known public DH.  The trusted members
   * include in their xor mask a combination of all anonymous DH keys with
   * their well known public DH.  In short, each peer has an xor mask for
   * each trusted peer.  Each trusted peer has an xor mask for every other
   * peer.  Their cleartext message is xored directly into the message.  Thus
   * after accumulating and xoring all the masks only the cleartext remains.
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
