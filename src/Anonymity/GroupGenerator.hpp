#ifndef DISSENT_ANONYMITY_GROUP_GENERATOR_H_GUARD
#define DISSENT_ANONYMITY_GROUP_GENERATOR_H_GUARD

#include "Group.hpp"

namespace Dissent {
namespace Anonymity {
  /**
   * Generates a subgroup from the provided group, in this case the subgroup
   * and group are identical.
   */
  class GroupGenerator {
    public:
      /**
       * CreateGroupGenerator static callback
       * @param group base group
       */
      explicit GroupGenerator(const Group &group) :
        _group(group)
      {
      }

      /**
       * CreateGroupGenerator static callback
       * @param group base group
       */
      static GroupGenerator *Create(const Group &group)
      {
        return new GroupGenerator(group);
      }

      /**
       * Destructor
       */
      virtual ~GroupGenerator() {}

      /**
       * Returns the next group to use
       */
      inline virtual const Group NextGroup() { return _group; }

      /**
       * Returns the last group returned via the NextGroup() method
       */
      inline virtual const Group CurrentGroup() const { return _group; }

      /**
       * Returns the entire group
       */
      inline const Group WholeGroup() const { return _group; }

      /**
       * Updates the core group
       */
      inline virtual void Update(const Group &group) { _group = group; }

    private:
      Group _group;
  };

  /**
   * A callback method for static constructor access for GroupGenerator objects
   */
  typedef GroupGenerator *(*CreateGroupGenerator)(const Group &);
}
}

#endif
