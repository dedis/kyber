#ifndef DISSENT_WEB_SERVICES_SESSION_WEB_SERVICE_GUARD
#define DISSENT_WEB_SERVICES_SESSION_WEB_SERVICE_GUARD

#include <QSharedPointer>

#include "Anonymity/Session.hpp"

#include "WebService.hpp"

namespace Dissent {
namespace Web {
namespace Services {
  
  namespace {
    using namespace Dissent::Anonymity;
  }

  /**
   * A WebService that has access to the 
   * anonymity Session object
   */
  class SessionWebService : public WebService {

    public:

      SessionWebService(QSharedPointer<Session> session);
      
    protected:
      
      QSharedPointer<Session> _session;

  };

}
}
}

#endif
