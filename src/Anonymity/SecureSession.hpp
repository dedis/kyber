#ifndef DISSENT_ANONYMITY_SECURE_SESSION_H_GUARD
#define DISSENT_ANONYMITY_SECURE_SESSION_H_GUARD

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
      typedef Round *(*CreateSecureRound)(const Id &, const Group &,
          const ConnectionTable &, RpcHandler &, const Id &, AsymmetricKey *key,
          const QByteArray &);

      /**
       * Constructor
       * @param local_id the local node's ID
       * @param leader_id the Id of the leader
       * @param group an ordered member of peers for the group
       * @param ct maps Ids to connections
       * @param rpc for sending and receives remote procedure calls
       * @param signing_key the local nodes private signing key, pointer NOT
       * owned by this object
       */
      SecureSession(const Id &local_id, const Id &leader_id, const Group &group,
          ConnectionTable &ct, RpcHandler &rpc, const Id &session_id,
          AsymmetricKey *signing_key, CreateSecureRound create_round,
          const QByteArray &default_data);

    private:
      AsymmetricKey *_signing_key;
      CreateSecureRound _create_secure_round;

      virtual Round *GetRound(const QByteArray &data);
  };
}
}

#endif
