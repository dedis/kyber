#ifndef DISSENT_UTILS_START_STOP_H_GUARD
#define DISSENT_UTILS_START_STOP_H_GUARD

#include <QString>

namespace Dissent {
namespace Utils {
  /**
   * A thin class to encapsulate the common start / stop pattern
   */
  class StartStop {
    public:
      /**
       * Constructor
       */
      explicit StartStop();

      /**
       * Destructor - Please call destructor check in your code!
       */
      virtual ~StartStop() {}

      /**
       * Returns true if started the first time
       */
      virtual bool Start();

      /**
       * Returns true if the first time stopped
       */
      virtual bool Stop();

      /**
       * Returns true if the first time stopped
       * @param reason the reason for stopping
       */
      virtual bool Stop(const QString &reason);

      /**
       * Returns true if started
       */
      virtual bool Started() const { return _started; }

      /**
       * Returns true if stopped
       */
      virtual bool Stopped() const { return _stopped; }

      virtual QString GetStoppedReason() const { return _stop_reason; }

    protected:
      /**
       * Ensures the StartStop object has been Stopped, must be explicitly
       * called in inherited classes.
       */
      void DestructorCheck();

      virtual void OnStart() {}

      virtual void OnStop() {}

    private:
      bool _started;
      bool _stopped;
      QString _stop_reason;
  };
}
}

#endif
