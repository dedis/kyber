#ifndef DISSENT_WEB_SESSION_SERVICE_GUARD
#define DISSENT_WEB_SESSION_SERVICE_GUARD

#include <QSharedPointer>
#include "Session/Session.hpp"
#include "WebService.hpp"

namespace Dissent {
namespace Web {
  /**
   * A WebService that has access to the anonymity Session object
   */
  class SessionService : public WebService {
    public:

      explicit SessionService(const QSharedPointer<Session::Session> &session);

      /**
       * Called to handle the incoming request
       * @param request the incoming request
       * @param response used to respond to the rqeuest
       */
      virtual void HandleRequest(QHttpRequest *request, QHttpResponse *response);

    protected:
      /**
       * Return the session
       */
      QSharedPointer<Session::Session> GetSession() { return m_session; }
 
    private:
      QSharedPointer<Session::Session> m_session;
  };
}
}

#endif
