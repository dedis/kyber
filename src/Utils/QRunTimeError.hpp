#ifndef DISSENT_UTILS_Q_RUN_TIME_ERROR_H_GUARD
#define DISSENT_UTILS_Q_RUN_TIME_ERROR_H_GUARD

#include <QString>

namespace Dissent {
namespace Utils {
  class QRunTimeError : public std::exception {
    public:
      QRunTimeError(const QString &msg) : _qwhat(msg) { }
      ~QRunTimeError() throw() { }
      inline const QString What() { return _qwhat; }
      virtual const char *what() throw() { return _qwhat.toUtf8().data(); }

    protected:
      const QString _qwhat;
  };
}
}

#endif
