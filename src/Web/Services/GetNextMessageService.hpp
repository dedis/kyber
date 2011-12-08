#ifndef DISSENT_WEB_SERVICES_GET_NEXT_MESSAGE_SERVICE_GUARD
#define DISSENT_WEB_SERVICES_GET_NEXT_MESSAGE_SERVICE_GUARD

#include <QVector>

#include "MessageWebService.hpp"

namespace Dissent {
namespace Web {
namespace Services {
  /** 
   *
   * WebService for getting the next available message from an Anonymity
   * Session. The connection is held open by the server until a message is
   * available.
   */
  class GetNextMessageService : public MessageWebService {
    public:
      virtual ~GetNextMessageService() {}

    private:
      /**
       * The main method for the web service.  If the status code wrp->status
       * is not STATUS_OK, then the output data might not be set.
       * @param request to be handled
       */
      virtual void Handle(QSharedPointer<WebRequest> wrp);

      virtual void HandleMessage(const QByteArray &data);
    
      QVector<QSharedPointer<WebRequest> > _pending_requests;
  };
}
}
}

#endif
