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
   */
  class FixedSizeGroupGenerator : public GroupGenerator {
    public:
      FixedSizeGroupGenerator(const Group &group, const Id &session_id,
          const ConnectionTable &ct, RpcHandler &rpc,
          QSharedPointer<AsymmetricKey> signing_key) :
        GroupGenerator(group, session_id, ct, rpc, signing_key)
      {
        QVector<Id> ids;
        QVector<QSharedPointer<AsymmetricKey> > keys;
        for(int idx = 0; idx < group.Count() && idx < 10; idx++) {
          ids.append(group.GetId(idx));
          keys.append(group.GetKey(idx));
        }
        _fixed_group.reset(new Group(ids, keys));
        _current = *_fixed_group;
      }

      static GroupGenerator *Create(const Group &group, const Id &session_id,
          const ConnectionTable &ct, RpcHandler &rpc,
          QSharedPointer<AsymmetricKey> signing_key)
      {
        return new FixedSizeGroupGenerator(group, session_id, ct, rpc, signing_key);
      }

      virtual const Group NextGroup()
      {
        return _current;
      }

    private:
      QScopedPointer<Group> _fixed_group;
  };
}
}

#endif
