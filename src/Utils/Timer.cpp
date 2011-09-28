#include "Timer.hpp"
#include <QDebug>

namespace Dissent {
namespace Utils {
  Timer::Timer() : _next_timer(-1)
  {
    _queue = TimerQueue(&(TimerEvent::ReverseComparer));
    _running = false;
    _stopped = true;
    UseRealTime();
  }

  Timer::~Timer()
  {
    Stop();
  }

  Timer& Timer::GetInstance()
  {
    static Timer timer;
    return timer;
  }

  void Timer::QueueEvent(TimerEvent te)
  {
    _queue.push(te);
    if(_queue.top() == te && _real_time) {
      if(_next_timer != -1) {
        killTimer(_next_timer);
      }
      qint64 next = Run();
      if(next > -1) {
        _next_timer = startTimer(next);
      }
    }
  }

  TimerEvent Timer::QueueCallback(TimerCallback *callback, int due_time)
  {
    TimerEvent te(callback, due_time);
    QueueEvent(te);
    return te;
  }

  TimerEvent Timer::QueueCallback(TimerCallback *callback, int due_time, int period)
  {
    TimerEvent te(callback, due_time, period);
    QueueEvent(te);
    return te;
  }

  void Timer::UseVirtualTime()
  {
    _real_time = false;
    Stop();
    Time::GetInstance().UseVirtualTime();
  }

  void Timer::UseRealTime()
  {
    _real_time = true;
    Start();
    Time::GetInstance().UseRealTime();
  }

  void Timer::Stop()
  {
    if(!_running) {
      return;
    }

    _running = false;
    _stopped = true;
  }

  void Timer::Start()
  {
    if(_running || !_stopped) {
      return;
    }
    _running = true;
    _stopped = false;
  }

  void Timer::timerEvent(QTimerEvent *event)
  {
    killTimer(event->timerId());
    qint64 next = Run();
    if(next > -1) {
      _next_timer = startTimer(next);
    }
  }

  qint64 Timer::Run()
  {
    int next = -1;

    while(true) {
      if(_queue.empty()) {
        next = -1;
        break;
      }

      TimerEvent te = _queue.top();
      if(te.GetNextRun() <= Time::GetInstance().MSecsSinceEpoch()) {
        _queue.pop();
        te.Run();
        if(te.GetPeriod() > 0) {
          _queue.push(te);
        }
      } else {
        next = te.GetNextRun() - Time::GetInstance().MSecsSinceEpoch();
        break;
      }
    }
    return next;
  }

  qint64 Timer::VirtualRun()
  {
    if(_real_time) {
      return -1;
    }
    return Run();
  }
}
}
