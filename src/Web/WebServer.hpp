#ifndef DISSENT_WEB_WEB_SERVER_H_GUARD
#define DISSENT_WEB_WEB_SERVER_H_GUARD

#include <QScopedPointer>
#include <QSharedPointer>

#include "qhttpserver.h"
#include "qhttprequest.h"
#include "qhttpresponse.h"

#include "Utils/StartStopSlots.hpp"
#include "WebService.hpp"

namespace Dissent {
namespace Web {
  class WebServer : public Utils::StartStopSlots {
    Q_OBJECT

    public:
      WebServer(const QUrl &host);

      virtual ~WebServer();

      /**
       * Called to start
       */
      virtual bool Start();

      /**
       * Called to stop
       */
      virtual bool Stop();

      /**
       * Add a route to the routing table.
       * @param method the method to route (GET, POST, etc)
       * @param path the base path to route (without query string)
       * @param service the routing destination service
       * @returns returns true if successfully added
       */
      bool AddRoute(QHttpRequest::HttpMethod method, const QString &path,
          const QSharedPointer<WebService> &service);

    private:
      typedef QPair<QHttpRequest::HttpMethod, QString> ServiceId;
      QHash<ServiceId, QSharedPointer<WebService> > m_services;
      QScopedPointer<QHttpServer> m_server;
      QUrl m_host;
      QHash<QHttpRequest *, QHttpResponse *> m_requests;

    private slots:
      void HandleRequest(QHttpRequest *request, QHttpResponse *response);
      void RequestReady();

  };
}
}
#endif
