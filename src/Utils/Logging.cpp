#include <QFile>
#include "Logging.hpp"
#include "Time.hpp"

namespace Dissent {
namespace Utils {
  QString Logging::_filename;

  void Logging::UseFile(const QString &filename)
  {
    _filename = filename;
    qInstallMsgHandler(File);
  }

  void Logging::File(QtMsgType type, const char *msg)
  {
    QFile file(_filename);
    if(file.open(QFile::WriteOnly | QIODevice::Text | QIODevice::Append)) {
      QTextStream stream(&file);
      Write(stream, type, msg);
    }
  }

  void Logging::UseStdout()
  {
    qInstallMsgHandler(Stdout);
  }

  void Logging::Stdout(QtMsgType type, const char *msg)
  {
    QTextStream stream(stdout, QIODevice::WriteOnly);
    Write(stream, type, msg);
  }

  void Logging::UseStderr()
  {
    qInstallMsgHandler(Stderr);
  }

  void Logging::Stderr(QtMsgType type, const char *msg)
  {
    QTextStream stream(stderr, QIODevice::WriteOnly);
    Write(stream, type, msg);
  }

  void Logging::Write(QTextStream &stream, QtMsgType type, const char *msg)
  {
    stream << Time::GetInstance().CurrentTime().toString(Qt::ISODate) << " - ";

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
    qInstallMsgHandler(0);
  }

  void Logging::Disable()
  {
    qInstallMsgHandler(Disabled);
  }

  void Logging::Disabled(QtMsgType, const char *)
  {
  }
}
}
