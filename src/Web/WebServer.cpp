#include "WebServer.hpp"

namespace Dissent {
namespace Web {
  WebServer::WebServer(const QUrl &host) :
    m_server(new QHttpServer()),
    m_host(host)
  {
    connect(m_server.data(), SIGNAL(newRequest(QHttpRequest *, QHttpResponse *)),
        this, SLOT(HandleRequest(QHttpRequest *, QHttpResponse *)));
  }

  WebServer::~WebServer()
  {
    Stop();
  }

  bool WebServer::Start()
  {
    if(!StartStopSlots::Start()) {
      return false;
    }

    Q_ASSERT(m_server->listen(QHostAddress(m_host.host()), m_host.port(8080)));
    return true;
  }

  bool WebServer::Stop()
  {
    if(!StartStopSlots::Stop()) {
      return false;
    }

    m_server->close();
    m_server.reset();
    return true;
  }

  bool WebServer::AddRoute(QHttpRequest::HttpMethod method,
      const QString &path, const QSharedPointer<WebService> &service)
  {
    ServiceId sid(method, path);
    if(m_services.contains(sid)) {
      return false;
    }

    m_services[sid] = service;
    return true;
  }

  void WebServer::HandleRequest(QHttpRequest *request, QHttpResponse *response)
  {
    // Clean up when done
    QObject::connect(response, SIGNAL(done()), request, SLOT(deleteLater()));
    // Receive the requests data
    request->storeBody();
    QObject::connect(request, SIGNAL(end()), this, SLOT(RequestReady()));

    m_requests[request] = response;
  }

  void WebServer::RequestReady()
  {
    QHttpRequest *request = qobject_cast<QHttpRequest *>(sender());
    Q_ASSERT(request);

    QHttpResponse *response = m_requests[request];
    Q_ASSERT(response);

    ServiceId sid(request->method(), request->path());
    if(m_services.contains(sid)) {
      qDebug() << "Handling request for" << request->url();
      m_services[sid]->HandleRequest(request, response);
    } else {
      qDebug() << "Invalid request for" << request->url();
      response->writeHead(QHttpResponse::STATUS_NOT_FOUND);
      response->end();
    }
  }
}
}
