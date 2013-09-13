#ifndef DISSENT_ANONYMITY_BUDDIES_BUDDY_MONITOR_H_GUARD
#define DISSENT_ANONYMITY_BUDDIES_BUDDY_MONITOR_H_GUARD

#include <QBitArray>
#include <QList>
#include <QSharedPointer>
#include "BuddyPolicy.hpp"

#define MIN_SIZE 1
#define BUDDY_SIZE 1

namespace Dissent {
namespace Anonymity {
namespace Buddies {
  /**
   * @class BuddyMonitor currently assumes a 1-to-1 mapping between Nyms and
   * members. This monitor implements a version of the "Hang with Your Buddies
   * to Resist Intersection Attacks;" however, it lacks the features that allow
   * for uniformly randomly assigned nyms and continuation of nyms across rounds.
   * Calculations in this version take into consideration the 1-to-1 mapping
   * and certain metrics have meaning only within this context.
   */
  class BuddyMonitor {
    public:
      /**
       * @param bp Implementation of the BuddyPolicy (Buddies)
       * @param min_anon the minimum number cardinality for any anonymity set
       */
      BuddyMonitor(const QSharedPointer<BuddyPolicy> &bp,
          int min_anon = 0);

      /**
       * Called first to set the members who submitted a ciphertext
       */
      void SetOnlineMembers(const QBitArray &members);

      /**
       * Specify that a nym has been used
       */
      void SetActiveNym(int idx);

      /**
       * Specify that a whole set of nyms have been used
       */
      void SetActiveNyms(const QBitArray &nyms);

      /**
       * For interactive protocols inquire which nyms to reveal
       */
      QBitArray ShouldRevealNyms(const QBitArray &nyms);

      /**
       * Returns the list of members to include in the anonymity system
       */
      QBitArray GetUsefulMembers() const;

      /**
       * Returns the total number of members (and pseudonyms)
       */
      int GetCount() const { return m_bp->GetCount(); }

      /**
       * Returns a conservative anonymity metric, assumes any active member
       * has deanonymized themself. Unique for 1-to-1.
       */
      int GetConservativeAnonymity(int idx) const;

      /**
       * Returns the number of potential owners of a given Nym.
       */
      int GetNymAnonymity(int idx) const;

      /**
       * Returns the number of Nyms that may be owned by the given Member.
       * Unique for 1-to-1.
       */
      int GetMemberAnonymity(int idx) const;

      double GetMemberScore(int idx) const;
      double GetNymScore(int idx) const;
    private:
      static void SetActiveNym(int idx, const QBitArray &useful_members,
          QBitArray &member_set, QBitArray &nym_set);

      QSharedPointer<BuddyPolicy> m_bp;

      QList<QBitArray> m_member_set;
      QList<QBitArray> m_nym_set;

      QBitArray m_used_nyms;
      int m_min_anon;
  };
}
}
}
#endif
