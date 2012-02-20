#ifndef DISSENT_IDENTITY_GROUP_HOLDER_H_GUARD
#define DISSENT_IDENTITY_GROUP_HOLDER_H_GUARD

#include <QObject>

#include "Group.hpp"

namespace Dissent {
namespace Identity {
  /**
   * Maintains an evolving group
   */
  class GroupHolder : public QObject {
    Q_OBJECT

    public:
      /**
       * Constructor
       */
      GroupHolder(const Group &group = Group()) : _group(group) { }

      /**
       * Update the maintained group
       * @param group the new group
       */
      void UpdateGroup(const Group &group)
      {
        _group = group;
        emit GroupUpdated();
      }

      /**
       * Returns the current instance of the group
       */
      const Group GetGroup() const { return _group; }

    signals:
      /**
       * Emitted when the group has been updated
       */
      void GroupUpdated() const;

    private:
      Group _group;
  };
}
}

#endif
