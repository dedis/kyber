#ifndef DISSENT_WEB_SERVICES_GET_NEXT_MESSAGE_SERVICE_GUARD
#define DISSENT_WEB_SERVICES_GET_NEXT_MESSAGE_SERVICE_GUARD

#include <QObject>
#include <QSet>

#include "Web/WebRequest.hpp"
#include "MessageWebService.hpp"

namespace Dissent {
namespace Web {
namespace Services {
   
  namespace {
    using namespace Dissent::Web;
  }

  /** 
   * WebService for getting the next available message
   * from an Anonymity Session. The connection is held
   * open by the server until a message is available.
   */
  class GetNextMessageService : public MessageWebService {
    Q_OBJECT

    public:
      
      GetNextMessageService();

      virtual ~GetNextMessageService();

      /**
       * The main method for the web service. 
       * If the status code wrp->status 
       * is not STATUS_OK, then the
       * output data might not be set.
       * @param request to be handled
       */
      void Handle(QSharedPointer<WebRequest> wrp);

    public slots:
      virtual void HandleIncomingMessage(const QByteArray &data);
    
    private:
      QSet<QSharedPointer<WebRequest> > _pending_requests;

  };

}
}
}

#endif
