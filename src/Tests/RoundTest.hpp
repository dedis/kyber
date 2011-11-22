#include "TestNode.hpp"

namespace Dissent {
namespace Tests {
  class BadGuyCB {
    public:
      virtual bool operator()(Round *) const = 0;
  };

  template<typename T> class BadGuyCBTemplate : public BadGuyCB {
    public:
      virtual bool operator()(Round *pr) const
      {
        T *pt = dynamic_cast<T *>(pr);
        if(pt) {
          return pt->Triggered();
        }
        return false;
      }
  };

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
      CreateSessionCallback bad_callback, CreateGroupGenerator cgg,
      const BadGuyCB &cb, bool keys = false);
}
}
