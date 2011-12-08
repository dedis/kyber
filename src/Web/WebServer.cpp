#include <QByteArray>
#include <QDebug>
#include <QTcpSocket>
#include <QTextStream>

#include "HttpRequest.hpp"
#include "HttpResponse.hpp"
#include "WebRequest.hpp" 

#include "Web/Packagers/JsonPackager.hpp"

#include "Web/Services/GetMessagesService.hpp"
#include "Web/Services/RoundIdService.hpp"
#include "Web/Services/SendMessageService.hpp"
#include "Web/Services/SessionIdService.hpp"

#include "WebServer.hpp"

namespace Dissent {
namespace Web {

  namespace {
    using namespace Dissent::Web::Services;
    using namespace Dissent::Web::Packagers;
  }

  WebServer::WebServer(QHostAddress host, quint16 port) :
    QTcpServer(0),
    _host(host),
    _port(port),
    _running(false),
    _ready(false),
    _qtin(stdin, QIODevice::ReadOnly),
    _qtout(stdout, QIODevice::WriteOnly),
    _qtin_notify(STDIN_FILENO, QSocketNotifier::Read)
  {
  }

  WebServer::~WebServer()
  {
    Stop();

    qDebug() << "Destroying Web Server";

    QSet<QSharedPointer<WebService> >::iterator j;
    for(j=_service_set.begin(); j!=_service_set.end(); j++) {
      disconnect(j->data(), SIGNAL(FinishedWebRequest(QSharedPointer<WebRequest>)), 
            this, SLOT(HandleFinishedWebRequest(QSharedPointer<WebRequest>)));
    }

   _routing_table.clear();
   _service_set.clear();
  }

  void WebServer::Start()
  {
    if(_running) {
      return;
    }

    connect(&_qtin_notify, SIGNAL(activated(int)), this, SLOT(HandleStdin()));
    _qtin_notify.setEnabled(true);

    listen(_host, _port);

    _running = true;

    _qtout << "Server started on " << _host.toString() << ":" 
          << _port << ". Type 'quit' to exit." << endl;
  }

  void WebServer::Stop()
  {
    qDebug() << "Stopping!";
    if(!_running) {
      return;
    }

    _qtin_notify.setEnabled(false);
    disconnect(&_qtin_notify, SIGNAL(activated(int)), this, SLOT(HandleStdin()));

    /* stop listening */
    close();

    _running = false;

    /* kill the application */
    emit Stopped();
  }

  void WebServer::Ready()
  {
    _ready = true;
  }

  void WebServer::incomingConnection(int socket)
  {
    QTcpSocket* s = new QTcpSocket(this);
    connect(s, SIGNAL(readyRead()), this, SLOT(ReadFromClient()));
    connect(s, SIGNAL(disconnected()), this, SLOT(DiscardClient()));
    connect(s, SIGNAL(error(QAbstractSocket::SocketError)), 
        SLOT(HandleError(QAbstractSocket::SocketError)));
    s->setSocketDescriptor(socket);

    qDebug() << "New incoming connectionz";
  }


  void WebServer::HandleStdin()
  {
    QString msg = _qtin.readLine();
    if(msg == "quit") {
      _qtout << "Stopping web server." << endl;
      Stop();
    } else {
      _qtout << "Ignoring unknown command. Type 'quit' to exit." << endl;
    }
  }

  void WebServer::ReadFromClient()
  {
    HttpResponse::StatusCode status = HttpResponse::STATUS_INTERNAL_SERVER_ERROR;

    QTcpSocket* socket = qobject_cast<QTcpSocket*>(sender());
    if(!socket) {
      qFatal("Illegal call to ReadFromClient()");
    }

    /* Response object for error messages */
    HttpResponse response;

    QSharedPointer<WebRequest> wr(new WebRequest(socket));
    QByteArray request_data(wr->GetSocket()->readAll());

    if(wr->GetRequest().ParseRequest(request_data)) {
      wr->GetRequest().PrintDebug();
     
      QSharedPointer<WebService> service = GetRoute(wr->GetRequest()); 
      if(service.isNull()) {
        /* No service found to handle the request */
        status = HttpResponse::STATUS_NOT_FOUND;
      } else {
        qDebug() << "Server: calling service";
        service->Call(wr);
        qDebug() << "Server: finished calling service";
        return;
      }

    } else {
      /* Malformed request */
      status = HttpResponse::STATUS_BAD_REQUEST;
    }

    ReturnError(wr->GetSocket(), status); 
  }

  void WebServer::HandleError(QAbstractSocket::SocketError) 
  {
    QTcpSocket* socket = qobject_cast<QTcpSocket*>(sender());
    if(!socket) {
      qFatal("Illegal call to HandleError()");
    }
    qWarning() << "Socket error: " << qPrintable(socket->errorString());
  }
  
  void WebServer::DiscardClient()
  {
    /* We do NOT delete the socket here, since it
     * will be deleted when the WebRequest
     * has been processed by
     * HandleFinishedWebRequest()
     */
     
    qDebug() << "Socket closed";
  }

  QSharedPointer<WebService> WebServer::GetRoute(HttpRequest &request) {
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
      connect(service.data(), SIGNAL(FinishedWebRequest(QSharedPointer<WebRequest>)), 
            this, SLOT(HandleFinishedWebRequest(QSharedPointer<WebRequest>)));
    }

    _service_set.insert(service);
  }

  void WebServer::HandleFinishedWebRequest(QSharedPointer<WebRequest> wrp)
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

    JsonPackager pack;
    HttpResponse response;
    response.SetStatusCode(wrp->GetStatus());

    QVariantMap package_data;
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
  }

  void WebServer::ReturnError(QTcpSocket* socket, HttpResponse::StatusCode status)
  {
    HttpResponse response;

    response.AddHeader("Content-Type", "text/html");
    response.SetStatusCode(status);

    response.body << "<html><body>";
    response.body << "<h1>Error ";
    response.body << (int)status;
    response.body << ": ";
    response.body << response.TextForStatus(status);
    response.body << "</h1>\n";
    response.body << "</body></html>\n";

    response.WriteToSocket(socket);
  }

}
}
