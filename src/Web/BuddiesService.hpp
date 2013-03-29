#ifndef DISSENT_WEB_BUDDIES_SERVICE_GUARD
#define DISSENT_WEB_BUDDIES_SERVICE_GUARD

#include "SessionService.hpp"

namespace Dissent {
namespace Web {
  /**
   * A WebService that has access to the anonymity Session object
   */
  class BuddiesService : public SessionService {
    public:
      explicit BuddiesService(SessionManager &sm);

      /**
       * Called to handle the incoming request
       * @param request the incoming request
       * @param response used to respond to the rqeuest
       */
      virtual void HandleRequest(QHttpRequest *request, QHttpResponse *response);

    private:
      typedef Anonymity::Buddies::BuddyMonitor BuddyMonitor;
  };
}
}

#endif
