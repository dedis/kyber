#ifndef DISSENT_UTILS_START_STOP_H_GUARD
#define DISSENT_UTILS_START_STOP_H_GUARD

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
       * Returns true if started
       */
      virtual bool Started() { return _started; }

      /**
       * Returns true if stopped
       */
      virtual bool Stopped() { return _stopped; }

    protected:
      /**
       * Ensures the StartStop object has been Stopped, must be explicitly
       * called in inherited classes.
       */
      void DestructorCheck();

    private:
      bool _started;
      bool _stopped;
  };
}
}

#endif
