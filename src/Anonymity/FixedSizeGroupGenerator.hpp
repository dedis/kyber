#ifndef DISSENT_ANONYMITY_FIXED_SIZE_GROUP_GENERATOR_H_GUARD
#define DISSENT_ANONYMITY_FIXED_SIZE_GROUP_GENERATOR_H_GUARD

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
       */
      FixedSizeGroupGenerator(const Group &group) :
        GroupGenerator(group)
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
       */
      static GroupGenerator *Create(const Group &group)
      {
        return new FixedSizeGroupGenerator(group);
      }

      inline virtual const Group NextGroup() { return _current; }

      inline virtual const Group CurrentGroup() const { return _current; }

    private:
      Group _current;
  };
}
}

#endif
