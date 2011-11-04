#ifndef DISSENT_UTILS_LOGGING_H_GUARD
#define DISSENT_UTILS_LOGGING_H_GUARD

#include <QtCore>
#include <QString>
#include <QTextStream>

namespace Dissent {
namespace Utils {
  /**
   * Interface into Qt's logging system
   */
  class Logging {
    public:
      /**
       * Store all logs into the specified file
       * @param filename the file in which to store logs
       */
      static void UseFile(const QString &filename);

      /**
       * Output logs to stdout
       */
      static void UseStdout();

      /**
       * Output logs to stderr
       */
      static void UseStderr();

      /**
       * Use the default logging mechanism
       */
      static void UseDefault();

      /**
       * Disable logging
       */
      static void Disable();

    private:
      static QString _filename;
      static void File(QtMsgType type, const char *msg);
      static void Stdout(QtMsgType type, const char *msg);
      static void Stderr(QtMsgType type, const char *msg);
      static void Write(QTextStream &stream, QtMsgType type, const char *msg);
      static void Disabled(QtMsgType type, const char *msg);
  };
}
}

#endif
