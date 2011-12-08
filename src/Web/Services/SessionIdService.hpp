#ifndef DISSENT_WEB_SERVICES_SESSION_ID_SERVICE_GUARD
#define DISSENT_WEB_SERVICES_SESSION_ID_SERVICE_GUARD

#include <QObject>

#include "SessionWebService.hpp"

namespace Dissent {
namespace Web {
namespace Services {
  /**
   * WebService for returning the ID of the current anonymity session.
   */
  class SessionIdService : public SessionWebService {
    public:
      SessionIdService(QSharedPointer<Node> node);

      virtual ~SessionIdService() {}

    private:
      /**
       * The main method for the web service. If the status code wrp->status
       * is not STATUS_OK, then the output data might not be set.
       * @param request to be handled
       */
      virtual void Handle(QSharedPointer<WebRequest> wrp);
  };

}
}
}

#endif
