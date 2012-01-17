#ifndef DISSENT_UTILS_TIMER_EVENT_H_GUARD
#define DISSENT_UTILS_TIMER_EVENT_H_GUARD

#include <stdexcept>

#include <QtCore>
#include <QSharedData>
#include <QSharedDataPointer>

#include "Time.hpp"
#include "TimerCallback.hpp"

namespace Dissent {
namespace Utils {
  /**
   * Private data for TimerEvent, so that Pointers for TimerEvents are not requried
   */
  class TimerEventData : public QSharedData {
    public:
      explicit TimerEventData(TimerCallback *callback = 0, qint64 next = 0,
          int period = 0) :
        callback(callback),
        next(next),
        period(period),
        stopped(callback == 0),
        uid(_uid_count++)
      {
      }

      virtual ~TimerEventData() {}

      QScopedPointer<TimerCallback> callback;
      qint64 next;
      int period;
      bool stopped;
      int uid;

      TimerEventData(const TimerEventData &other) : QSharedData(other)
      {
        throw std::logic_error("Not callable");
      }

      TimerEventData &operator=(const TimerEventData &)
      {
        throw std::logic_error("Not callable");
      }

      private:
        static int _uid_count;
  };

  /**
   * Stores a Timer event, that is, a callback method, due time, and period
   */
  class TimerEvent {
    friend class Timer;

    public:
      explicit TimerEvent();
      TimerEvent(const TimerEvent &other);

      typedef bool(*ComparerFuncPtr)(const TimerEvent &, const TimerEvent &);
      static bool ReverseComparer(const TimerEvent &lhs, const TimerEvent &rhs);

      void Stop();
      inline qint64 GetNextRun() { return _state->next; }
      inline int GetPeriod() { return _state->period; }
      inline bool Stopped () { return _state->stopped; }

      bool operator<(const TimerEvent& other) const;
      bool operator>(const TimerEvent& other) const;
      bool operator==(const TimerEvent& other) const;
      bool operator!=(const TimerEvent& other) const;

    private:
      TimerEvent(TimerCallback *callback, int due_time, int period = 0);
      void Run();
      QExplicitlySharedDataPointer<TimerEventData> _state;
  };
}
}

#endif
