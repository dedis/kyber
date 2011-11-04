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
   */
  class GroupGenerator {
    public:
      GroupGenerator(const Group &group, const Id &session_id,
          const ConnectionTable &ct, RpcHandler &rpc,
          QSharedPointer<AsymmetricKey> signing_key) :
        _group(group),
        _current(group),
        _session_id(session_id),
        _ct(ct),
        _rpc(rpc),
        _signing_key(signing_key)
      {
      }

      static GroupGenerator *Create(const Group &group, const Id &session_id,
          const ConnectionTable &ct, RpcHandler &rpc,
          QSharedPointer<AsymmetricKey> signing_key)
      {
        return new GroupGenerator(group, session_id, ct, rpc, signing_key);
      }

      virtual const Group NextGroup() { return _group; }

      inline const Group CurrentGroup() const { return _current; }

    protected:
      const Group _group;
      Group _current;
      const Id _session_id;
      const ConnectionTable &_ct;
      RpcHandler &_rpc;
      QSharedPointer<AsymmetricKey> _signing_key;
  };

  /**
   */
  typedef GroupGenerator *(*CreateGroupGenerator)(const Group &,
      const Id &, const ConnectionTable &, RpcHandler &,
      QSharedPointer<AsymmetricKey>);
}
}

#endif
