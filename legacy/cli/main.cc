#include <QtCrypto>
#include <QCoreApplication>
#include <QScopedPointer>
#include <QString>

#include "config.hpp"
#include "node.hpp"

#include "handler.hpp"

int main(int argc, char* argv[]){
    Dissent::Crypto::GetInstance();
    QCoreApplication app(argc, argv);
    Dissent::Configuration config(argc, argv);

    Dissent::Node node(config);
    Handler handler(config.my_node_id, argc, argv);
    QObject::connect(
            &node, SIGNAL(shuffledDataReady(QList<QByteArray>)),
            &handler, SLOT(ShuffledData(QList<QByteArray>)));
    QObject::connect(
            &node, SIGNAL(protocolStarted(int)),
            &handler, SLOT(ProtocolStarted(int)));
    QObject::connect(
            &node, SIGNAL(stepEnded(QString)),
            &handler, SLOT(StepEnded(QString)));
    QObject::connect(
            &handler, SIGNAL(finish()),
            &node, SLOT(StopProtocol()));
    QObject::connect(
            &handler, SIGNAL(moreData(QByteArray)),
            &node, SLOT(EnterData(QByteArray)));
    node.StartProtocol();
    handler.Start();
    return app.exec();
}
