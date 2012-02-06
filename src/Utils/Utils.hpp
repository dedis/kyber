#ifndef DISSENT_UTILS_UTILS_H_GUARD
#define DISSENT_UTILS_UTILS_H_GUARD

#include <QString>

namespace Dissent {
namespace Utils {
  /**
   * Prints current resource usage
   * @param label an additional bit of logging information
   */
  void PrintResourceUsage(const QString &label);
}
}

#endif
