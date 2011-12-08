#ifndef DISSENT_WEB_SERVICES_ROUND_ID_SERVICE_GUARD
#define DISSENT_WEB_SERVICES_ROUND_ID_SERVICE_GUARD

#include <QObject>

#include "Web/WebRequest.hpp"
#include "SessionWebService.hpp"

namespace Dissent {
namespace Web {
namespace Services {

  namespace {
    using namespace Dissent::Web;
  }

  /**
   * WebService that returns the ID of the
   * current anonymity session round.
   */
  class RoundIdService : public SessionWebService {

    public:
      
      RoundIdService(QSharedPointer<Session> session);

      virtual ~RoundIdService();

      /**
       * The main method for the web service. 
       * If the status code wrp->status 
       * is not STATUS_OK, then the
       * output data might not be set.
       * @param request to be handled
       */
      void Handle(QSharedPointer<WebRequest> wrp);

  };

}
}
}

#endif
