#ifndef DISSENT_UTILS_SLEEPER_H_GUARD
#define DISSENT_UTILS_SLEEPER_H_GUARD

#include <QThread>

namespace Dissent {
namespace Utils {
  class Sleeper : QThread {
    public:
      /**
       * Suspend the current thread
       * @param secs time in seconds to sleep
       */
      static void Sleep(unsigned long secs);

      /**
       * Suspend the current thread
       * @param msecs time in milliseconds to sleep
       */
      static void MSleep(unsigned long msecs);

    private:
      explicit Sleeper();
      ~Sleeper();
      Sleeper(Sleeper const&);
      void operator=(Sleeper const&);
  };
}
}

#endif
