#ifndef DISSENT_WEB_WEB_REQUEST_H_GUARD
#define DISSENT_WEB_WEB_REQUEST_H_GUARD

#include <QObject>
#include <QTcpSocket>
#include <QVariant>

#include "HttpRequest.hpp"
#include "HttpResponse.hpp"

namespace Dissent {
namespace Web {

  /**
   * WebRequest holds all of the data that
   * a web service needs to process a request
   * and return a response data object
   */
  class WebRequest : public QObject {
    Q_OBJECT

    public:
      /**
       * Constructor
       */
      WebRequest(QTcpSocket* socket);
      
      ~WebRequest();

      inline QTcpSocket* GetSocket() { Q_ASSERT(_socket); return _socket; }

      inline HttpRequest& GetRequest() { return _request; }

      inline QVariant& GetOutputData() { return _output_data; }

      inline HttpResponse::StatusCode GetStatus() { return _status; }

      inline void SetStatus(HttpResponse::StatusCode status) { _status = status; }

    private:
      
      QTcpSocket* _socket;
      HttpRequest _request;

      QVariant _output_data;
      HttpResponse::StatusCode _status;

  };
}
}

#endif
