
#include "WebRequest.hpp"

namespace Dissent {
namespace Web {

  WebRequest::WebRequest(QTcpSocket* socket) :
    _socket(socket),
    _status(HttpResponse::STATUS_INTERNAL_SERVER_ERROR)
  {
  };

  WebRequest::~WebRequest() 
  {
    Q_ASSERT(_socket);
    _socket->flush();
    _socket->close();
    _socket->deleteLater();
  };

}
}
