#ifndef DISSENT_WEB_SERVICES_SESSION_WEB_SERVICE_GUARD
#define DISSENT_WEB_SERVICES_SESSION_WEB_SERVICE_GUARD

#include <QSharedPointer>

#include "../../Applications/Node.hpp"
#include "../../Anonymity/Session.hpp"

#include "WebService.hpp"

namespace Dissent {
namespace Web {
namespace Services {
  /**
   * A WebService that has access to the anonymity Session object
   */
  class SessionWebService : public WebService {
    public:
      typedef Dissent::Anonymity::Session Session;
      typedef Dissent::Applications::Node Node;

      /* 
       * Having two constructors here is a hack. Sometimes the session is
       * not set up when we want to instantiate a service -- in those cases
       * we pass in the Node. Other times (in Test), the Node is not easy to
       * fake, so we use Session.
       */
      explicit SessionWebService(QSharedPointer<Session> session) : _use_node(false), _session(session) {}
      explicit SessionWebService(QSharedPointer<Node> node) : _use_node(true), _node(node) {}

      virtual ~SessionWebService() {}

    protected:
      /**
       * Return the monitored session
       */
      QSharedPointer<Session> GetSession() { return (_use_node ? _node->session : _session); }
 
    private:
      bool _use_node;
      QSharedPointer<Node> _node;
      QSharedPointer<Session> _session;
  };
}
}
}

#endif
