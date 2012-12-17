#include "bodydata.h"

#include <QCoreApplication>
#include <QRegExp>
#include <QStringList>
#include <QDebug>

#include <qhttpserver.h>
#include <qhttprequest.h>
#include <qhttpresponse.h>

Responder::Responder(QHttpRequest *req, QHttpResponse *resp)
    : QObject(0)
    , m_req(req)
    , m_resp(resp)
{
    QRegExp exp("^/user/([a-z]+$)");
    if( exp.indexIn(req->path()) != -1 )
    {
        resp->setHeader("Content-Type", "text/html");
        resp->writeHead(200);
        QString name = exp.capturedTexts()[1];

        QString reply = tr("<html><head><title>BodyData App</title></head><body><h1>Hello  %1!</h1><p>").arg(name);
        resp->write(reply);
    }
    else
    {
        resp->writeHead(403);
        resp->end("You aren't allowed here!");
        // TODO: there should be a way to tell request to stop streaming data
        return;
    }
    connect(m_req, SIGNAL(data(const QByteArray&)), this, SLOT(accumulate(const QByteArray&)));
    connect(req, SIGNAL(end()), this, SLOT(reply()));
    connect(resp, SIGNAL(done()), this, SLOT(deleteLater()));
}

Responder::~Responder()
{
    qDebug() << "DELETING" << m_req;
    delete m_req;
    m_req = 0;
}

void Responder::accumulate(const QByteArray &data)
{
    m_resp->write(data);
}

void Responder::reply()
{
    m_resp->end(QString("</p></body></html>").toAscii());
}

BodyData::BodyData()
{
    QHttpServer *server = new QHttpServer;
    server->listen(QHostAddress::Any, 5000);
    connect(server, SIGNAL(newRequest(QHttpRequest*, QHttpResponse*)),
            this, SLOT(handle(QHttpRequest*, QHttpResponse*)));
}

void BodyData::handle(QHttpRequest *req, QHttpResponse *resp)
{
    Responder *r = new Responder(req, resp);
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);

    BodyData hello;
    
    app.exec();
}
