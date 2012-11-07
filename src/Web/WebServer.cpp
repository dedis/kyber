#include <QByteArray>
#include <QDebug>
#include <QTcpSocket>
#include <QTextStream>

#include "HttpRequest.hpp"
#include "HttpResponse.hpp"
#include "WebRequest.hpp" 

#include "Web/Packagers/JsonPackager.hpp"

#include "WebServer.hpp"

namespace Dissent {
namespace Web {
  namespace {
    using namespace Dissent::Web::Packagers;
  }

  WebServer::WebServer(QUrl url) :
    QTcpServer(0),
    _host(url.host()),
    _port(url.port(8080)),
    _running(false)
  {
  }

  WebServer::~WebServer()
  {
    Stop();

    qDebug() << "Destroying Web Server";

    for(int i=0; i<_service_set.count(); i++) {
      disconnect(_service_set[i].data(),
          SIGNAL(FinishedWebRequest(QSharedPointer<WebRequest>, bool)),
          this, SLOT(HandleFinishedWebRequest(QSharedPointer<WebRequest>, bool)));
    }

   _routing_table.clear();
   _service_set.clear();
  }

  void WebServer::Start()
  {
    if(_running) {
      return;
    }

    listen(_host, _port);
    _running = true;
  }

  void WebServer::Stop()
  {
    qDebug() << "Stopping!";
    if(!_running) {
      return;
    }

    /* stop listening */
    close();

    _running = false;

    /* kill the application */
    emit Stopped();
  }

  void WebServer::incomingConnection(int socket)
  {
    QTcpSocket* s = new QTcpSocket(this);
    s->setSocketDescriptor(socket);
    QSharedPointer<WebRequest> request(new WebRequest(s));
    _web_requests.insert(request.data(), request);

    connect(request.data(), SIGNAL(Finished(bool)),
        SLOT(HandleWebRequest(bool)));

    connect(request.data(), SIGNAL(ResponseFinished()),
        SLOT(HandleWebRequestFinished()));

    qDebug() << "New incoming connection";
  }

  void WebServer::HandleWebRequestFinished()
  {
    WebRequest *wr = qobject_cast<WebRequest *>(sender());
    QSharedPointer<WebRequest> wrs = _handled_web_requests.value(wr);
    if(!wrs) {
      // *Probably the currently handle request*
      // or some nasty bug...
      return;
    }
    _handled_web_requests.remove(wr);
  }

  void WebServer::HandleWebRequest(bool success)
  {
    HttpResponse::StatusCode status = HttpResponse::STATUS_INTERNAL_SERVER_ERROR;

    WebRequest *wr = qobject_cast<WebRequest *>(sender());
    QSharedPointer<WebRequest> wrs = _web_requests.value(wr);
    if(!wrs) {
      // *Probably the currently handle request*
      // or some nasty bug...
      return;
    }
    _web_requests.remove(wr);
    _handled_web_requests.insert(wr, wrs);

    /* Response object for error messages */
    HttpResponse response;

    if(success) {
      QSharedPointer<WebService> service = GetRoute(wrs->GetRequest()); 
      if(service.isNull()) {
        /* No service found to handle the request */
        status = HttpResponse::STATUS_NOT_FOUND;
      } else {
        qDebug() << "Server: calling service";
        service->Call(wrs);
        qDebug() << "Server: finished calling service";
        return;
      }
    } else {
      /* Malformed request */
      status = HttpResponse::STATUS_BAD_REQUEST;
    }

    ReturnError(wrs->GetSocket(), status); 
  }

  QSharedPointer<WebServer::WebService> WebServer::GetRoute(const HttpRequest &request)
  {
    QPair<HttpRequest::RequestMethod, QString> pair;
    pair.first = request.GetMethod();
    pair.second = request.GetPath();

    if(_routing_table.contains(pair)) {
      return _routing_table[pair];
    }

    return QSharedPointer<WebService>();
  }

  void WebServer::AddRoute(HttpRequest::RequestMethod method, 
      QString path,
      QSharedPointer<WebService> service)
  {
    QPair<HttpRequest::RequestMethod, QString> pair;
    pair.first = method;
    pair.second = path;

    _routing_table.insert(pair, service);
   
    /* Only connect each WebService instance once */
    if(!_service_set.contains(service)) {
      connect(service.data(), SIGNAL(FinishedWebRequest(QSharedPointer<WebRequest>, bool)),
          this, SLOT(HandleFinishedWebRequest(QSharedPointer<WebRequest>, bool)));
    }

    _service_set.append(service);
  }

  void WebServer::HandleFinishedWebRequest(QSharedPointer<WebRequest> wrp,
      bool format)
  {
    qDebug() << "Finished Web Request!";

    if(!wrp) {
      qFatal("In HandleFinishedWebRequest(): pointer is NULL");
    }
    /* Before doing anything, make sure that the connection
     * is still open */
    if(!wrp->GetSocket()->isWritable()) {
      return;
    }

    if(wrp->GetStatus() != HttpResponse::STATUS_OK) {
      ReturnError(wrp->GetSocket(), wrp->GetStatus());
      return;
    }

    QVariant data = wrp->GetOutputData();
    if(data.isNull() || !data.isValid()) {
      qWarning("Invalid output data!");
    
      ReturnError(wrp->GetSocket(), HttpResponse::STATUS_INTERNAL_SERVER_ERROR);
      return;
    }

    HttpResponse response;
    response.SetStatusCode(wrp->GetStatus());

    if(format) {
      JsonPackager pack;

      QVariantHash package_data;
      package_data["copyright"] = "2011 by Yale University";
      package_data["api_version"] = QString("%1.%2.%3")
          .arg(API_MajorVersionNumber)
          .arg(API_MinorVersionNumber)
          .arg(API_BuildVersionNumber);
      package_data["output"] = wrp->GetOutputData();

      QVariant flattened(package_data);

      if(!pack.Package(flattened, response)) {
        qWarning("Could not package output data!");
      
        ReturnError(wrp->GetSocket(), HttpResponse::STATUS_INTERNAL_SERVER_ERROR);
        return;
      }
  
      response.WriteToSocket(wrp->GetSocket());
    } else {
      response.body << wrp->GetOutputData().toString();
      response.WriteToSocket(wrp->GetSocket());
    }
  }

  void WebServer::ReturnError(QTcpSocket* socket, HttpResponse::StatusCode status)
  {
    HttpResponse response;
    response.AddHeader("Content-Type", "text/html");
    response.SetStatusCode(status);
    response.WriteToSocket(socket);
  }

}
}
