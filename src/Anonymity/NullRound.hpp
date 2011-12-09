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
       * @param creds the local nodes credentials
       * @param round_id unused
       * @param network handles message sending
       * @param get_data requests data to share during this session
       */
      explicit NullRound(QSharedPointer<GroupGenerator> group_gen,
          const Credentials &creds, const Id &round_id, 
          QSharedPointer<Network> network, GetDataCallback &get_data);

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
