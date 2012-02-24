#ifndef DISSENT_MESSAGING_REQUEST_HANDLER_H_GUARD
#define DISSENT_MESSAGING_REQUEST_HANDLER_H_GUARD

#include <QObject>

namespace Dissent {
namespace Messaging {
  class Request;

  /**
   * Used to create a request callback, note this does NOT keep a pointer,
   * it internally uses slots and signals and func *must* be a valid slot.
   */
  class RequestHandler : public QObject {
    Q_OBJECT

    public:
      /**
       * Constructor
       * @param obj owner of the method
       * @param func function name in the object
       */
      RequestHandler(const QObject *obj, const char *func)
      {
        QString slot = QString::number(QSLOT_CODE) + func +
          "(const Request &)" + QLOCATION;

        QObject::connect(this,
            SIGNAL(MakeRequestSignal(const Request &)),
            obj,
            slot.toUtf8().data());
      }

      /**
       * Destructor
       */
      virtual ~RequestHandler() {}

      /**
       * Called by the RpcHandler when a request for this method is called
       * @param request the request
       */
      inline void MakeRequest(const Request &request) const
      {
        emit MakeRequestSignal(request);
      }

    signals:
      /**
       * Signal emitted by MakeRequest to call into the slot associated w/ this signal
       * @param request the request
       */
      void MakeRequestSignal(const Request &request) const;
  };
}
}

#endif
