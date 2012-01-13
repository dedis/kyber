#ifndef DISSENT_UTILS_START_STOP_SLOTS_H_GUARD
#define DISSENT_UTILS_START_STOP_SLOTS_H_GUARD

#include <QObject>

#include "StartStop.hpp"

namespace Dissent {
namespace Utils {
  /**
   * A thin class to encapsulate the common start / stop pattern
   */
  class StartStopSlots : public QObject, public StartStop {
    Q_OBJECT

    public:
      /**
       * Destructor - Please call destructor check in your code!
       */
      virtual ~StartStopSlots() {}

    public slots:
      /**
       * Calls start
       */
      void CallStart()
      {
        Start();
      }

      /**
       * Calls stop
       */
      void CallStop()
      {
        Stop();
      }
  };
}
}

#endif
