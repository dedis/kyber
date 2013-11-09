#include "Anonymity/BaseDCNetRound.hpp"
#include "Anonymity/CSDCNetRound.hpp"
#include "Anonymity/NeffShuffleRound.hpp"
#include "Anonymity/NullRound.hpp"

#include "RoundFactory.hpp"

namespace Dissent {
namespace Anonymity {
  CreateRound RoundFactory::GetCreateRound(RoundType type)
  {
    CreateRound cr;
    switch(type) {
      case NULL_ROUND:
        cr = &TCreateRound<NullRound>;
        break;
      case NEFF_SHUFFLE:
        cr = &TCreateRound<NeffShuffleRound>;
        break;
      case NULL_CSDCNET:
        cr = &TCreateDCNetRound<CSDCNetRound, NullRound>;
        break;
      case NEFF_CSDCNET:
      case VERDICT_CSDCNET:
      default:
        qFatal("Invalid round type");
    }
    return cr;
  }
}
}
