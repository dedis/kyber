#ifndef DISSENT_ANONYMITY_BUDDIES_BUDDY_MONITOR_H_GUARD
#define DISSENT_ANONYMITY_BUDDIES_BUDDY_MONITOR_H_GUARD

#include <QBitArray>
#include <QList>
#include <QSharedPointer>
#include "BuddyPolicy.hpp"

namespace Dissent {
namespace Anonymity {
namespace Buddies {
  class BuddyMonitor {
    public:
      BuddyMonitor(const QSharedPointer<BuddyPolicy> &bp);
      void SetOnlineMembers(const QBitArray &members);
      void SetActiveNym(int idx);
      void SetActiveNyms(const QBitArray &nyms);
      bool ShouldRevealNym(int idx);
      QBitArray GetUsefulMembers() const;
      QBitArray GetNymsToReveal() const;

      int GetConservativeAnonymity(int idx) const;
      int GetNymAnonymity(int idx) const;
      int GetMemberAnonymity(int idx) const;
      double GetMemberScore(int idx) const;
      double GetNymScore(int idx) const;
    private:
      QSharedPointer<BuddyPolicy> m_bp;

      QList<QBitArray> m_member_set;
      QList<QBitArray> m_nym_set;

      QBitArray m_used_nyms;
  };
}
}
}
#endif
