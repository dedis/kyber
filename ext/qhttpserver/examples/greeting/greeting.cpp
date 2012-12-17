#include "greeting.h"

#include <QCoreApplication>
#include <QRegExp>
#include <QStringList>

#include <qhttpserver.h>
#include <qhttprequest.h>
#include <qhttpresponse.h>

Greeting::Greeting()
{
    QHttpServer *server = new QHttpServer;
    server->listen(QHostAddress::Any, 5000);
    connect(server, SIGNAL(newRequest(QHttpRequest*, QHttpResponse*)),
            this, SLOT(handle(QHttpRequest*, QHttpResponse*)));
}

void Greeting::handle(QHttpRequest *req, QHttpResponse *resp)
{
    QRegExp exp("^/user/([a-z]+)$");
    if( exp.indexIn(req->path()) != -1 )
    {
        resp->setHeader("Content-Type", "text/html");
        resp->writeHead(200);
        QString name = exp.capturedTexts()[1];

        QString reply = tr("<html><head><title>Greeting App</title></head><body><h1>Hello %1!</h1></body></html>");
        resp->end(reply.arg(name).toAscii());
    }
    else
    {
        resp->writeHead(403);
        resp->end("You aren't allowed here!");
    }
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);

    Greeting hello;
    
    app.exec();
}
