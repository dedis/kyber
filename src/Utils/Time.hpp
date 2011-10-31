#ifndef DISSENT_UTILS_TIME_H_GUARD
#define DISSENT_UTILS_TIME_H_GUARD

#include <QDateTime>

namespace Dissent {
namespace Utils {
  /**
   * Presents a wrapper around Qt DateTime to support real and virtual time
   */
  class Time {
    public:
      /**
       * Access the Time singleton
       */
      static Time& GetInstance();

      /**
       * Get a QDateTime of the current time
       */
      QDateTime CurrentTime();

      /**
       * Returns the number of milliseconds since the epoch
       */
      qint64 MSecsSinceEpoch();

      /**
       * Time returns time based upon the system clock
       */
      void UseRealTime();

      /**
       * Time returns time based upon a user controlled clock
       */
      void UseVirtualTime();

      /**
       * Returns whether or not real time is being used
       */
      inline bool UsingRealTime() { return _real_time; }

      /**
       * Increment the user controlled (Virtual) clock
       * @param time the number of milliseconds to increment the virtual clock by
       */
      void IncrementVirtualClock(qint64 time);

    protected:

      /**
       * Stores the current virtual clock
       */
      qint64 _current_virtual_time;

#if QT_VERSION < 0x040700
      /**
       * The Epoch!
       */
      QDateTime _epoch;

      static const qint64 MSecsPerDay;
#endif


      /**
       * Disabled for singleton
       */
      Time();

      /**
       * Disabled for singleton
       */
      Time(Time const&);

      /**
       * Disabled for singleton
       */
      void operator=(Time const&);

      bool _real_time;
  };
}
}

#endif
