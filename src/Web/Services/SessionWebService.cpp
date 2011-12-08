
#include "SessionWebService.hpp"

namespace Dissent {
namespace Web {
namespace Services {

  SessionWebService::SessionWebService(QSharedPointer<Session> session) :
    WebService(),
    _session(session)
  {
  };

}
}
}
