#ifndef DISSENT_ANONYMITY_BUDDIES_BUDDY_POLICY_H_GUARD
#define DISSENT_ANONYMITY_BUDDIES_BUDDY_POLICY_H_GUARD

#include <QBitArray>
#include <QList>

namespace Dissent {
namespace Anonymity {
namespace Buddies {
  /**
   * @class BuddyPolicy
   * The basic construction for organizing members to have identical behavior.
   */
  class BuddyPolicy {
    public:
      /**
       * Base constructor
       * @param count number of members
       */
      BuddyPolicy(int count);

      virtual ~BuddyPolicy() {}

      /**
       * Specify the members online at this interval
       * @param members the set of members
       */
      void SetOnlineMembers(const QBitArray &members);

      /**
       * Returns the useful members as computed by the underlying protocol
       */
      QBitArray GetUsefulMembers() const;

      /**
       * Returns the group id for online buddies
       * who have not yet been assigned a group
       */
      int OnlineUnallocatedBuddy() const { return -1; }

      /**
       * Returns the group id for offline buddies
       * who have not yet been assigned a group
       */
      int OfflineUnallocatedBuddy() const { return -2; }

      /**
       * Returns the number of members
       */
      inline int GetCount() const { return m_count; }

      /**
       * Returns the online members
       */
      inline QBitArray GetOnlineMembers() const { return m_online_members; }

    protected:
      /**
       * Called as a result of SetOnlineMembers
       */
      virtual void UpdateBuddies() = 0;

      /**
       * Appends a group to the set of groups returning the new groups index.
       * Group indexes are assigned incrementally, so using GetTotalGroups
       * will return the next group index.
       * @param group the group to append
       */
      int AppendGroup(const QList<int> &group);

      /**
       * Returns the total number of groups as well as the next group index.
       */
      int GetTotalGroups() const { return m_groups.size(); }

      /**
       * Sets a member into a specific group
       * @param uid the member id
       * @param gid the group id
       */
      void SetMemberGroup(int uid, int gid) { m_members[uid] = gid; }

    private:
      int m_count;
      QList<QList<int> > m_groups;
      QList<int> m_members;
      QList<bool> m_online;
      QBitArray m_online_members;
  };
}
}
}

#endif
