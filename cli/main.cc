#include <QtCrypto>
#include <QCoreApplication>
#include <QScopedPointer>

#include "config.hpp"
#include "crypto.hpp"
#include "node.hpp"
#include "node_impl_bulk.hpp"

#include "handler.hpp"

int main(int argc, char* argv[]){
    Dissent::Crypto::GetInstance();
    QCoreApplication app(argc, argv);
    Dissent::Configuration config(argc, argv);

    Dissent::Node node(config);
    Handler handler(config.my_node_id);
    QObject::connect(
            &node, SIGNAL(shuffledDataReady(QList<QByteArray>)),
            &handler, SLOT(ShuffledData(QList<QByteArray>)));
    QObject::connect(
            &handler, SIGNAL(finish()),
            &node, SLOT(StopProtocol()));
    QObject::connect(
            &handler, SIGNAL(moreData(QByteArray)),
            &node, SLOT(EnterData(QByteArray)));
    node.StartProtocol();
    switch(config.my_node_id){
        case 1:
            node.EnterData("This is a secret.");
            break;
        case 2:
            node.EnterData("This is another secret.");
            break;
        case 3:
            node.EnterData("This is yet another secret.");
            break;
        default:
            qFatal("node id not in range");
    }
    return app.exec();
}
