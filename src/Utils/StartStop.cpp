#include "StartStop.hpp"

namespace Dissent {
namespace Utils {
  StartStop::StartStop() :
    _started(false),
    _stopped(false)
  {
  }

  bool StartStop::Start()
  {
    if(_started || _stopped) {
      return false;
    }

    _started = true;
    OnStart();
    return true;
  }

  bool StartStop::Stop()
  {
    return Stop("Explicit");
  }

  bool StartStop::Stop(const QString &reason)
  {
    if(_stopped) {
      return false;
    }

    _stopped = true;
    _stop_reason = reason;
    OnStop();
    return true;
  }

  void StartStop::DestructorCheck()
  {
    if(!Stopped() && Started()) {
      Stop("Destructor");
    }
  }
}
}
