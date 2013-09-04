#include <QFile>
#include "Logging.hpp"
#include "Time.hpp"

namespace Dissent {
namespace Utils {
  QString Logging::_filename;

  void Logging::UseFile(const QString &filename)
  {
    _filename = filename;
#if QT_VERSION < QT_VERSION_CHECK(5, 0, 0)
    qInstallMsgHandler(File);
#else
    qInstallMessageHandler(File);
#endif
  }

#if QT_VERSION < QT_VERSION_CHECK(5, 0, 0)
  void Logging::File(QtMsgType type, const char *msg)
#else
  void Logging::File(QtMsgType type, const QMessageLogContext &,
      const QString &msg)
#endif
  {
    QFile file(_filename);
    if(file.open(QFile::WriteOnly | QIODevice::Text | QIODevice::Append)) {
      QTextStream stream(&file);
      Write(stream, type, msg);
    }
  }

  void Logging::UseStdout()
  {
#if QT_VERSION < QT_VERSION_CHECK(5, 0, 0)
    qInstallMsgHandler(Stdout);
#else
    qInstallMessageHandler(Stdout);
#endif
  }

#if QT_VERSION < QT_VERSION_CHECK(5, 0, 0)
  void Logging::Stdout(QtMsgType type, const char *msg)
#else
  void Logging::Stdout(QtMsgType type, const QMessageLogContext &,
      const QString &msg)
#endif
  {
    QTextStream stream(stdout, QIODevice::WriteOnly);
    Write(stream, type, msg);
  }

  void Logging::UseStderr()
  {
#if QT_VERSION < QT_VERSION_CHECK(5, 0, 0)
    qInstallMsgHandler(Stderr);
#else
    qInstallMessageHandler(Stderr);
#endif
  }

#if QT_VERSION < QT_VERSION_CHECK(5, 0, 0)
  void Logging::Stderr(QtMsgType type, const char *msg)
#else
  void Logging::Stderr(QtMsgType type, const QMessageLogContext &,
      const QString &msg)
#endif
  {
    QTextStream stream(stderr, QIODevice::WriteOnly);
    Write(stream, type, msg);
  }

#if QT_VERSION < QT_VERSION_CHECK(5, 0, 0)
  void Logging::Write(QTextStream &stream, QtMsgType type, const char *msg)
#else
  void Logging::Write(QTextStream &stream, QtMsgType type, const QString &msg)
#endif
  {
    stream << Time::GetInstance().CurrentTime().toString("yyyy-MM-ddThh:mm:ss.zzz") << " - ";

    switch(type) {
      case QtDebugMsg:
        stream << "Debug - ";
        break;
      case QtWarningMsg:
        stream << "Warning - ";
        break;
      case QtCriticalMsg:
        stream << "Critical - ";
        break;
      case QtFatalMsg:
        stream << "Fatal - ";
        break;
      default:
        stream << "Unknown - ";
    }

    stream << msg << endl;
  }

  void Logging::UseDefault()
  {
#if QT_VERSION < QT_VERSION_CHECK(5, 0, 0)
    qInstallMsgHandler(0);
#else
    qInstallMessageHandler(0);
#endif
  }

  void Logging::Disable()
  {
#if QT_VERSION < QT_VERSION_CHECK(5, 0, 0)
    qInstallMsgHandler(Disabled);
#else
    qInstallMessageHandler(Disabled);
#endif
  }

#if QT_VERSION < QT_VERSION_CHECK(5, 0, 0)
  void Logging::Disabled(QtMsgType, const char *)
#else
  void Logging::Disabled(QtMsgType, const QMessageLogContext &, const QString &)
#endif
  {
  }
}
}
