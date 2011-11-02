#ifndef DISSENT_ANONYMITY_SECURE_SESSION_H_GUARD
#define DISSENT_ANONYMITY_SECURE_SESSION_H_GUARD

#include <QSharedPointer>

#include "Session.hpp"

namespace Dissent {
namespace Anonymity {
  namespace {
    using namespace Dissent::Messaging;
    using namespace Dissent::Connections;
  }

  /**
   * Maintains a group which is actively participating in anonymous exchanges
   * using cryptographic keys and what not
   */
  class SecureSession : public Session {
    public:
      typedef Round *(*CreateSecureRound)(const Group &, const Id &, const Id &,
          const Id &, const ConnectionTable &, RpcHandler &,
          QSharedPointer<AsymmetricKey>, const QByteArray &);

      /**
       * Constructor
       * @param group an ordered member of peers for the group
       * @param local_id the local node's ID
       * @param leader_id the Id of the leader
       * @param session_id Id for the session
       * @param ct maps Ids to connections
       * @param rpc for sending and receives remote procedure calls
       * @param signing_key the local nodes private signing key, pointer NOT
       * @param create_round a callback for creating a secure round
       * @param default_data default data
       */
      SecureSession(const Group &group, const Id &local_id,
          const Id &leader_id, const Id &session_id, ConnectionTable &ct,
          RpcHandler &rpc, QSharedPointer<AsymmetricKey> signing_key,
          CreateSecureRound create_round, const QByteArray &default_data);

      inline virtual QString ToString() { return "SecureSession: " + GetId().ToString(); }

    private:
      QSharedPointer<AsymmetricKey> _signing_key;
      CreateSecureRound _create_secure_round;

      virtual Round *GetRound(const QByteArray &data);
  };
}
}

#endif
