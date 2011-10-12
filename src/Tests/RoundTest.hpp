#include "TestNode.hpp"

namespace Dissent {
namespace Tests {
  void RoundTest_Null(CreateSessionCallback callback, bool keys = false);
  void RoundTest_Basic(CreateSessionCallback callback, bool keys = false);
  void RoundTest_MultiRound(CreateSessionCallback callback, bool keys = false);
  void RoundTest_PeerDisconnect(CreateSessionCallback callback, bool keys = false);
}
}
