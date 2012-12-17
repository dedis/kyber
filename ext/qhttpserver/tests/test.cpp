#include <QCoreApplication>
#include <QHostAddress>

#include <qhttpserver.h>

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);

    QHttpServer server;
    server.listen(QHostAddress::Any, 5000);

    app.exec();
}
