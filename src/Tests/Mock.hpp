#ifndef DISSENT_TESTS_MOCK_H_GUARD
#define DISSENT_TESTS_MOCK_H_GUARD

#include <qcoreapplication.h>

#include "Dissent.hpp"

namespace Dissent {
namespace Tests {
  inline void MockExecLoop(SignalCounter &sc, int interval = 0)
  {
    while(true) {
      QCoreApplication::processEvents();
      QCoreApplication::sendPostedEvents();
      if(sc.GetCount() == sc.Max()) {
        return;
      }
      Sleeper::MSleep(interval);
    }
  }

  inline void MockExec()
  {
    QCoreApplication::processEvents();
    QCoreApplication::sendPostedEvents();
  }
}
}
#endif
