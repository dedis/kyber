#include "Sleeper.hpp"

namespace Dissent {
namespace Utils {
  void Sleeper::Sleep(unsigned long secs)
  {
    QThread::sleep(secs);
  }

  void Sleeper::MSleep(unsigned long msecs)
  {
    QThread::msleep(msecs);
  }
}
}
