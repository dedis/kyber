#ifndef DISSENT_ANONYMITY_FIXED_SIZE_GROUP_GENERATOR_H_GUARD
#define DISSENT_ANONYMITY_FIXED_SIZE_GROUP_GENERATOR_H_GUARD

#include <QVector>

#include "GroupGenerator.hpp"

namespace Dissent {
namespace Anonymity {
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
        QVector<GroupContainer> gr = group.GetRoster();
        gr.resize(10);
        _current = Group(gr);
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
