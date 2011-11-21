#ifndef DISSENT_ANONYMITY_FIXED_SIZE_GROUP_GENERATOR_H_GUARD
#define DISSENT_ANONYMITY_FIXED_SIZE_GROUP_GENERATOR_H_GUARD

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
   * Generates a subgroup of a fixed length from the provided group
   */
  class FixedSizeGroupGenerator : public GroupGenerator {
    public:
      /**
       * Constructor
       * @param group base group
       * @param local_id the local nodes Id
       * @param session_id Id for the session
       * @param ct maps Ids to connections
       * @param rpc for sending and receives remote procedure calls
       * @param signing_key the local nodes private signing key, pointer NOT
       */
      FixedSizeGroupGenerator(const Group &group, const Id &local_id,
          const Id &session_id, const ConnectionTable &ct, RpcHandler &rpc,
          QSharedPointer<AsymmetricKey> signing_key) :
        GroupGenerator(group, local_id, session_id, ct, rpc, signing_key)
      {
        QVector<Id> ids;
        QVector<QSharedPointer<AsymmetricKey> > keys;
        for(int idx = 0; idx < group.Count() && idx < 10; idx++) {
          ids.append(group.GetId(idx));
          keys.append(group.GetKey(idx));
        }
        _current = Group(ids, keys);
      }

      /**
       * Destructor
       */
      virtual ~FixedSizeGroupGenerator() {}

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
        return new FixedSizeGroupGenerator(group, local_id, session_id, ct, rpc, signing_key);
      }

      inline virtual const Group NextGroup() { return _current; }

      inline virtual const Group CurrentGroup() const { return _current; }

    private:
      Group _current;
  };
}
}

#endif
