#include "TimerEvent.hpp"

namespace Dissent {
namespace Utils {
  int TimerEventData::_uid_count = 0;

  TimerEvent::TimerEvent(TimerCallback *callback, int due_time, int period) :
    _state(new TimerEventData(callback,
          Time::GetInstance().MSecsSinceEpoch() + due_time,
          period))
  {
  }

  TimerEvent::TimerEvent(const TimerEvent &other) : _state(other._state)
  {
  }

  void TimerEvent::Stop()
  {
    _state->stopped = true;
  }

  void TimerEvent::Run()
  {
    if(_state->stopped) {
      _state->period = 0;
      return;
    }

    _state->next += _state->period;
    _state->callback->Invoke();
  }

  bool TimerEvent::ReverseComparer(const TimerEvent &lhs, const TimerEvent &rhs)
  {
    return lhs > rhs;
  }

  bool TimerEvent::operator<(const TimerEvent& other) const
  {
    if(_state->next < other._state->next) {
      return true;
    } else if(_state->next > other._state->next) {
      return false;
    } else {
      return _state->uid < other._state->uid;
    }
  }

  bool TimerEvent::operator>(const TimerEvent& other) const
  {
    if(_state->next > other._state->next) {
      return true;
    } else if(_state->next < other._state->next) {
      return false;
    } else {
      return _state->uid > other._state->uid;
    }
  }

  bool TimerEvent::operator==(const TimerEvent& other) const
  {
    return _state->uid == other._state->uid;
  }

  bool TimerEvent::operator!=(const TimerEvent& other) const
  {
    return _state->uid != other._state->uid;
  }
}
}
