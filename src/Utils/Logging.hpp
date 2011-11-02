#ifndef DISSENT_UTILS_LOGGING_H_GUARD
#define DISSENT_UTILS_LOGGING_H_GUARD

#include <QtCore>
#include <QString>
#include <QTextStream>

namespace Dissent {
namespace Utils {
  class Logging {
    public:
      static void UseFile(const QString &filename);
      static void UseStdout();
      static void UseStderr();
      static void UseDefault();
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
