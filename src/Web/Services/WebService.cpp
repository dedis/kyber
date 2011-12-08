
#include "WebService.hpp"

namespace Dissent {
namespace Web {
namespace Services {

  WebService::WebService()
  {
    connect(this, SIGNAL(WebServiceCalled(QSharedPointer<WebRequest>)),
        this, SLOT(HandleWrapper(QSharedPointer<WebRequest>)));
  }

  WebService::~WebService() 
  {
    disconnect(this, SIGNAL(WebServiceCalled(QSharedPointer<WebRequest>)),
        this, SLOT(HandleWrapper(QSharedPointer<WebRequest>)));
  }

  void WebService::Call(QSharedPointer<WebRequest> wrp)
  {
    qDebug() << "Service: called!";
    emit WebServiceCalled(wrp);
    qDebug() << "Service: emitted 'called' signal";
  }

}
}
}
