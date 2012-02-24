#ifndef DISSENT_MESSAGING_RESPONSE_HANDLER_H_GUARD
#define DISSENT_MESSAGING_RESPONSE_HANDLER_H_GUARD

#include <QObject>

namespace Dissent {
namespace Messaging {
  class Response;

  /**
   * Used to create a response callback, note this does NOT keep a pointer,
   * it internally uses slots and signals and func *must* be a valid slot.
   */
  class ResponseHandler : public QObject {
    Q_OBJECT

    public:
      /**
       * Constructor
       * @param obj owner of the method
       * @param func function name in the object
       */
      ResponseHandler(const QObject *obj, const char *func)
      {
        QString slot = QString::number(QSLOT_CODE) + func +
          "(const Response &)" + QLOCATION;

        QObject::connect(this,
            SIGNAL(RequestCompleteSignal(const Response &)),
            obj,
            slot.toUtf8().data());
      }

      /**
       * Destructor
       */
      virtual ~ResponseHandler() {}

      /**
       * Called to initiate to pass the response to the actual handler
       * @param response the response to the request
       */
      void RequestComplete(const Response &response) const
      {
        emit RequestCompleteSignal(response);
      }

    signals:
      /**
       * Called when a response to a request comes back
       * @param response 
       */
      void RequestCompleteSignal(const Response &response) const;
  };
}
}

#endif
