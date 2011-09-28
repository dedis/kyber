#ifndef DISSENT_UTILS_TIMER_H_GUARD
#define DISSENT_UTILS_TIMER_H_GUARD

#include <queue>
#include <vector>

#include <QObject>
#include <QTimerEvent>
#include <QThread>

#include "TimerCallback.hpp"
#include "Time.hpp"
#include "TimerEvent.hpp"

namespace Dissent {
namespace Utils {
  /**
   * Timers should be allocated on a per-thread basis or this class needs to be
   * made thread-safe ... currently this is not thread-safe and is only a
   * singleton...
   */
  class Timer : public QObject {
    Q_OBJECT

    public:
      /**
       * Returns the Timer singleton
       */
      static Timer& GetInstance();

      /**
       * Timer and Time will be using virtual time
       */
      void UseVirtualTime();

      /**
       * Timer and Time will be using real time
       */
      void UseRealTime();

      /**
       * True if using real time
       */
      inline bool UsingRealTime() { return _real_time; }

      /**
       * Enqueue a future timed event
       */
      void QueueEvent(TimerEvent event);

      /**
       * Execute a callback at a future point in time
       * @param callback the callback to execute
       * @param due_time time in ms from now to execute the callback
       */
      TimerEvent QueueCallback(TimerCallback *callback, int due_time);

      /**
       * Execute a callback at a future point in time and each period thereafter
       * @param callback the callback to execute
       * @param due_time time in ms from now to execute the callback
       * @param period time in ms between follow up callbacks
       */
      TimerEvent QueueCallback(TimerCallback *callback, int due_time, int period);

      /**
       * When running Virtual time, executes all events scheduled up to the
       * current time and returns the next time an event is scheduled.
       */
      qint64 VirtualRun();

    protected:
      /**
       * Singleton, disabled
       */
      Timer();

      /**
       * Singleton, protected
       */
      ~Timer();

      /**
       * Singleton, disabled
       */
      Timer(Timer const&);

      /**
       * Singleton, disabled
       */
      void operator=(Timer const&);

      /**
       * Convenient typedef for the TimerEvent comparator
       */
      typedef std::priority_queue<TimerEvent, std::vector<TimerEvent>,
              TimerEvent::ComparerFuncPtr> TimerQueue;

      /**
       * Priority queue for storing the Timers
       */
      TimerQueue _queue;

      /**
       * Currently using real time
       */
      bool _real_time;

      /**
       * Real time thread is running
       */
      bool _running;

      /**
       * Real time thread isn't running
       */
      bool _stopped;

      /**
       * Executes all events scheduled up to the current time and returns the
       * next time an event is scheduled.
       */
      qint64 Run();

      /**
       * The QThread interface
       */
      virtual void timerEvent(QTimerEvent *event);

      /**
       * Starts the real time Timer thread
       */
      void Start();

      /**
       * Stops the real time Timer thread
       */
      void Stop();

      int _next_timer;
  };
}
}

#endif
