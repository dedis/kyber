#ifndef DISSENT_UTILS_UTILS_H_GUARD
#define DISSENT_UTILS_UTILS_H_GUARD

#include <QString>

namespace Dissent {
namespace Utils {
  extern bool MultiThreading;
  extern bool Testing;

  /**
   * Prints current resource usage
   * @param label an additional bit of logging information
   */
  void PrintResourceUsage(const QString &label);

  /**
   * Converts from a byte array to a base64 string
   * @param data byte array to convert to base 64
   * @returns a base64 encoded byte array
   */
  QByteArray ToUrlSafeBase64(const QByteArray &data);

  /**
   * Converts a base64 string into a byte array
   * @param base64 base64 string
   * @returns a base64 decoded byte array
   */
  QByteArray FromUrlSafeBase64(const QByteArray &base64);
}
}

#endif
