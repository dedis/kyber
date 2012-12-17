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

  template<typename T> bool WaitCallback(T *obj, bool (T::*callback)()const)
  {
    int count = 0;
    while(!(obj->*callback)() && ++count != 100) {
      MockExec();
      Sleeper::MSleep(10);
    }

    return count != 100;
  }

  template<typename T> bool WaitCallback(T *obj, bool (T::*callback)(int))
  {
    int count = 0;
    while(!(obj->*callback)(10) && ++count != 100) {
      MockExec();
    }
    return count != 100;
  }

  template<typename T> bool WaitCallback(T *obj, bool (T::*callback)(int, bool *))
  {
    int count = 0;
    while(!(obj->*callback)(10, 0) && ++count != 100) {
      MockExec();
    }
    return count != 100;
  }
}
}
#endif
