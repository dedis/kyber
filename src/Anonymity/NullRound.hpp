#ifndef DISSENT_ANONYMITY_NULL_ROUND_H_GUARD
#define DISSENT_ANONYMITY_NULL_ROUND_H_GUARD

#include "Round.hpp"

namespace Dissent {
namespace Anonymity {
  /**
   * A simple Dissent exchange.  Just broadcasts everyones message to everyone else
   */
  class NullRound : public Round {
    Q_OBJECT

    public:
      /**
       * Constructor
       * @param group_gen Generate groups for use during this round
       * @param local_id The local peers id
       * @param round_id unused
       * @param network handles message sending
       * @param signing_key unused
       * @param get_data requests data to share during this session
       */
      NullRound(QSharedPointer<GroupGenerator> group_gen, const Id &local_id,
          const Id &round_id, QSharedPointer<Network> network,
          QSharedPointer<AsymmetricKey> signing_key, GetDataCallback &get_data);

      /**
       * Destructor
       */
      virtual ~NullRound() {}

      virtual bool Start();

      inline virtual QString ToString() const { return "NullRound"; }

    protected:
      /**
       * Pushes the data into the subscribed Sink
       * @param data the data to push
       * @param id the source of the data
       */
      virtual void ProcessData(const QByteArray &data, const Id &id);

    private:
      /**
       * Don't receive from a remote peer more than once...
       */
      QList<Id> _received_from;
  };
}
}

#endif
