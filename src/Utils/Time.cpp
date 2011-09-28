#include "Time.hpp"

namespace Dissent {
namespace Utils {
  Time::Time()
  {
    _current_virtual_time = 0;
    _real_time = true;
  }

  Time& Time::GetInstance()
  {
    static Time time;
    return time;
  }

  QDateTime Time::CurrentTime()
  {
    if(_real_time) {
      return QDateTime::currentDateTimeUtc();
    } else {
      return QDateTime::fromMSecsSinceEpoch(_current_virtual_time);
    }
  }

  qint64 Time::MSecsSinceEpoch()
  {
    if(_real_time) {
      return QDateTime::currentMSecsSinceEpoch();
    } else {
      return _current_virtual_time;
    }
  }

  void Time::UseRealTime()
  {
    _real_time = true;
  }

  void Time::UseVirtualTime()
  {
    _real_time = false;
  }

  void Time::IncrementVirtualClock(qint64 time)
  {
    _current_virtual_time += time;
  }
}
}
