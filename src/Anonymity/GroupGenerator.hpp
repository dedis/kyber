#ifndef DISSENT_ANONYMITY_GROUP_GENERATOR_H_GUARD
#define DISSENT_ANONYMITY_GROUP_GENERATOR_H_GUARD

#include <QSharedPointer>

#include "Session.hpp"
#include "GroupGenerator.hpp"

namespace Dissent {
namespace Anonymity {
  namespace {
    using namespace Dissent::Messaging;
    using namespace Dissent::Connections;
  }

  /**
   * Generates a subgroup from the provided group, in this case the subgroup
   * and group are identical.
   */
  class GroupGenerator {
    public:
      /**
       * CreateGroupGenerator static callback
       * @param group base group
       * @param local_id the local nodes Id
       * @param session_id Id for the session
       * @param ct maps Ids to connections
       * @param rpc for sending and receives remote procedure calls
       * @param signing_key the local nodes private signing key, pointer NOT
       */
      GroupGenerator(const Group &group, const Id &local_id,
          const Id &session_id, const ConnectionTable &ct, RpcHandler &rpc,
          QSharedPointer<AsymmetricKey> signing_key) :
        _group(group),
        _local_id(local_id),
        _session_id(session_id),
        _ct(ct),
        _rpc(rpc),
        _signing_key(signing_key),
        _current(group)
      {
      }

      /**
       * CreateGroupGenerator static callback
       * @param group base group
       * @param local_id the local nodes Id
       * @param session_id Id for the session
       * @param ct maps Ids to connections
       * @param rpc for sending and receives remote procedure calls
       * @param signing_key the local nodes private signing key, pointer NOT
       */
      static GroupGenerator *Create(const Group &group, const Id &local_id,
          const Id &session_id, const ConnectionTable &ct, RpcHandler &rpc,
          QSharedPointer<AsymmetricKey> signing_key)
      {
        return new GroupGenerator(group, local_id, session_id, ct, rpc, signing_key);
      }

      /**
       * Destructor
       */
      virtual ~GroupGenerator() {}

      /**
       * Returns the next group to use
       */
      virtual const Group NextGroup() { return _group; }

      /**
       * Returns the last group returned via the NextGroup() method
       */
      inline const Group CurrentGroup() const { return _current; }

    protected:
      const Group _group;
      const Id _local_id;
      const Id _session_id;
      const ConnectionTable &_ct;
      RpcHandler &_rpc;
      QSharedPointer<AsymmetricKey> _signing_key;
      Group _current;
  };

  /**
   * A callback method for static constructor access for GroupGenerator objects
   */
  typedef GroupGenerator *(*CreateGroupGenerator)(const Group &, const Id &,
      const Id &, const ConnectionTable &, RpcHandler &,
      QSharedPointer<AsymmetricKey>);
}
}

#endif
