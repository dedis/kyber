#ifndef DISSENT_UTILS_Q_RUN_TIME_ERROR_H_GUARD
#define DISSENT_UTILS_Q_RUN_TIME_ERROR_H_GUARD

#include <QString>

namespace Dissent {
namespace Utils {
  /**
   * Qt doesn't use exceptions, this provides a nice wrapper around
   * std::runtime_error, in order to use QString
   */
  class QRunTimeError : public std::exception {
    public:
      /**
       * Constructor
       * @param msg stores the msg into what
       */
      QRunTimeError(const QString &msg) : _qwhat(msg) { }

      /**
       * Desstructor
       */
      virtual ~QRunTimeError() throw() { }

      /**
       * Returns the reason for the exception
       */
      virtual inline const QString What() { return _qwhat; }

      /**
       * Returns the reason for the exception
       */
      virtual const char *what() throw() { return _qwhat.toUtf8().data(); }

    protected:
      const QString _qwhat;
  };
}
}

#endif
