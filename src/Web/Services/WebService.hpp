#ifndef DISSENT_WEB_SERVICES_WEB_SERVICE_GUARD
#define DISSENT_WEB_SERVICES_WEB_SERVICE_GUARD

#include <QObject>
#include <QSharedPointer>

#include "Web/WebRequest.hpp"

namespace Dissent {
namespace Web {
namespace Services {
  /**
   * WebService is the abstract base class representing the logic for
   * processing a WebRequest. 
   */
  class WebService : public QObject {
    Q_OBJECT

    public:
      typedef Dissent::Web::WebRequest WebRequest;

      /**
       * Constructor
       */
      explicit WebService();
      
      virtual ~WebService();

      /**
       * The method used to wrap the Web Service implementation's Handle method
       * @param the web request to be handled
       */
      void Call(QSharedPointer<WebRequest> wrp);

    signals:
      /**
       * emitted internally when someone has called Call() on this service
       */
      void WebServiceCalled(QSharedPointer<WebRequest> wrp);

      /**
       * Emitted when a web request has been processed and is ready for the
       * server to pick it up. 
       * @param wrp pointer to the Web request. 
       * @param format whether to package using default packager (true) or
       * leave as raw
       */
      void FinishedWebRequest(QSharedPointer<WebRequest> wrp, bool format);

    private slots:
      inline void HandleWrapper(QSharedPointer<WebRequest> wrp)
      {
        return Handle(wrp);
      }

    private:
      /**
       * The main method for the web service. If the status code wrp->status 
       * is not STATUS_OK, then the output data might not be set.
       * @param request to be handled
       */
      virtual void Handle(QSharedPointer<WebRequest> wrp) = 0;
  };
}
}
}

#endif
