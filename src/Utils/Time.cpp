#include "Time.hpp"
#include "Timer.hpp"
#include <QDebug>

namespace Dissent {
namespace Utils {
  #if QT_VERSION < 0x040700
  const qint64 Time::MSecsPerDay = 86400000;
  #endif

  Time::Time()
  {
    _current_virtual_time = 0;
    _real_time = true;

#if QT_VERSION < 0x040700
    _epoch = QDateTime::fromString("1970-01-01T00:00:00.000", Qt::ISODate);
    _epoch.setTimeSpec(Qt::UTC);
#endif
  }

  Time& Time::GetInstance()
  {
    static Time time;
    return time;
  }

  QDateTime Time::CurrentTime()
  {
    if(_real_time) {
#if QT_VERSION < 0x040700
      return QDateTime::currentDateTime().toUTC();
#else
      return QDateTime::currentDateTimeUtc();
#endif
    } else {
#if QT_VERSION < 0x040700
      return _epoch.addMSecs(_current_virtual_time);
#else
      return QDateTime::fromMSecsSinceEpoch(_current_virtual_time);
#endif
    }
  }

  qint64 Time::MSecsSinceEpoch()
  {
    if(_real_time) {
#if QT_VERSION < 0x040700
      QDateTime now = QDateTime::currentDateTime().toUTC();
      int days = _epoch.date().daysTo(now.date());
      int msecs = _epoch.time().msecsTo(now.time());
      qint64 msecs_total = (days * MSecsPerDay) + msecs;
      return msecs_total;
#else
      return QDateTime::currentMSecsSinceEpoch();
#endif
    } else {
      return _current_virtual_time;
    }
  }

  void Time::UseRealTime()
  {
    if(_real_time) {
      return;
    }

    _real_time = true;
    Timer::GetInstance().UseRealTime();
  }

  void Time::UseVirtualTime()
  {
    if(!_real_time) {
      return;
    }

    _real_time = false;
    Timer::GetInstance().UseVirtualTime();
  }

  void Time::IncrementVirtualClock(qint64 time)
  {
    _current_virtual_time += time;
  }
}
}
