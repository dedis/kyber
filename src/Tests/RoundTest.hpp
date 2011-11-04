#include "TestNode.hpp"

namespace Dissent {
namespace Tests {
  void RoundTest_Null(CreateSessionCallback callback,
      CreateGroupGenerator cgg, bool keys = false);
  void RoundTest_Basic(CreateSessionCallback callback,
      CreateGroupGenerator cgg, bool keys = false);
  void RoundTest_MultiRound(CreateSessionCallback callback,
      CreateGroupGenerator cgg, bool keys = false);
  void RoundTest_PeerDisconnectEnd(CreateSessionCallback callback,
      CreateGroupGenerator cgg, bool keys = false);
  void RoundTest_PeerDisconnectMiddle(CreateSessionCallback callback,
      CreateGroupGenerator cgg, bool keys = false);
  void RoundTest_BadGuy(CreateSessionCallback good_callback,
      CreateSessionCallback bad_callback,
      CreateGroupGenerator cgg, bool keys = false);
}
}
