#ifndef DISSENT_ANONYMITY_ROUND_FACTORY_H_GUARD
#define DISSENT_ANONYMITY_ROUND_FACTORY_H_GUARD

#include <QHash>

#include "Round.hpp"

namespace Dissent {
namespace Anonymity {

  /**
   * Generates an appropriate round given the input
   */
  class RoundFactory {
    public:
      static const char* RoundNames(int id)
      {
        static const char* rounds[] = {
          "null",
          "neffshuffle",
          "neff/csdcnet",
          "null/csdcnet",
          "verdict/csdcnet"
        };
        return rounds[id];
      }

      enum RoundType {
        INVALID = -1,
        NULL_ROUND = 0,
        NEFF_SHUFFLE,
        NEFF_CSDCNET,
        NULL_CSDCNET,
        VERDICT_CSDCNET,
        NOT_A_ROUND
      };

      static RoundType GetRoundType(const QString &stype)
      {
        static QHash<QString, RoundType> string_to_type = BuildStringToTypeHash();
        return string_to_type.value(stype, INVALID);
      }

      static CreateRound GetCreateRound(const QString &type)
      {
        return GetCreateRound(GetRoundType(type));
      }

      static CreateRound GetCreateRound(RoundType type);

    private:
      static QHash<QString, RoundType> BuildStringToTypeHash()
      {
        QHash<QString, RoundType> hash;
        for(int idx = NULL_ROUND; idx < NOT_A_ROUND; idx++) {
          hash[RoundNames(idx)] = static_cast<RoundType>(idx);
        }
        return hash;
      }

      Q_DISABLE_COPY(RoundFactory)
  };
}
}

#endif
