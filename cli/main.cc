#include <QtCrypto>
#include <QCoreApplication>
#include <QScopedPointer>

#include "config.hpp"
#include "crypto.hpp"
#include "node.hpp"
#include "node_impl_bulk.hpp"

#include "handler.hpp"

#define MAX_NODE_ID 3

void InitializeDummyConfig(int node_id, Dissent::Configuration* config);

int main(int argc, char* argv[]){
    Q_ASSERT(argc > 1);
    bool ok = false;
    int node_id = QString(argv[1]).toInt(&ok);
    Q_ASSERT_X(ok, "main", "converting argv[1] to integer failed");
    Q_ASSERT(node_id >= 1 && node_id <= MAX_NODE_ID);

    Dissent::Crypto::GetInstance();
    QCoreApplication app(argc, argv);
    Dissent::Configuration config;
    InitializeDummyConfig(node_id, &config);

    Dissent::Node node(config);
    Handler handler(node_id);
    QObject::connect(
            &node, SIGNAL(shuffledDataReady(const QList<QByteArray>&)),
            &handler, SLOT(ShuffledData(const QList<QByteArray>&)));
    QObject::connect(
            &handler, SIGNAL(finish()),
            &node, SLOT(StopProtocol()));
    QObject::connect(
            &handler, SIGNAL(moreData(const QByteArray&)),
            &node, SLOT(EnterData(const QByteArray&)));
    node.StartProtocol();
    switch(node_id){
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
            qFatal("wtf");
    }
    return app.exec();
}

void InitializeDummyConfig(int node_id, Dissent::Configuration* config){
    QCA::ConvertResult convert_result;
    QCA::PublicKey pk = QCA::PublicKey::fromPEMFile("pk1.pem", &convert_result);
    Q_ASSERT(convert_result == QCA::ConvertGood);
    Q_ASSERT(pk.isRSA());
    Dissent::PublicKey node1_pk = pk.toRSA();

    pk = QCA::PublicKey::fromPEMFile("pk2.pem", &convert_result);
    Q_ASSERT(convert_result == QCA::ConvertGood);
    Q_ASSERT(pk.isRSA());
    Dissent::PublicKey node2_pk = pk.toRSA();

    pk = QCA::PublicKey::fromPEMFile("pk3.pem", &convert_result);
    Q_ASSERT(convert_result == QCA::ConvertGood);
    Q_ASSERT(pk.isRSA());
    Dissent::PublicKey node3_pk = pk.toRSA();

    const static char* const filename[MAX_NODE_ID + 1] = {
        "", "sk1.pem", "sk2.pem", "sk3.pem",
    };
    QCA::PrivateKey sk = QCA::PrivateKey::fromPEMFile(
            filename[node_id],
            QCA::SecureArray(), &convert_result);
    Q_ASSERT(convert_result == QCA::ConvertGood);
    Q_ASSERT(sk.isRSA());
    Dissent::PrivateKey node_sk = sk.toRSA();

    Dissent::NodeInfo node1_info = {
        1, "127.0.0.1", 12345, node1_pk, false };
    Dissent::NodeInfo node2_info = {
        2, "127.0.0.1", 12346, node2_pk, false };
    Dissent::NodeInfo node3_info = {
        3, "127.0.0.1", 12347, node3_pk, false };

    config->my_node_id = node_id;
    config->identity_sk = node_sk;
    config->nodes.clear();
    config->nodes.insert(1, node1_info);
    config->nodes.insert(2, node2_info);
    config->nodes.insert(3, node3_info);
    config->num_nodes = config->nodes.size();
    config->disposable_key_length = 1024;
    config->shuffle_msg_length = -1;  // set later

    Dissent::NodeTopology tp1 = { 1, 2, -1};
    Dissent::NodeTopology tp2 = { 2, 3, 1};
    Dissent::NodeTopology tp3 = { 3, -1, 2};
    config->topology.clear();
    config->topology.push_back(tp1);
    config->topology.push_back(tp2);
    config->topology.push_back(tp3);
    config->my_position = node_id - 1;
    config->protocol_version = Dissent::Configuration::DISSENT_VERSION_1;

    QByteArray ba("");
    Dissent::BulkSend::MessageDescriptor desc(config);
    desc.Initialize(ba);
    desc.Serialize(&ba);
    config->shuffle_msg_length = ba.size();
    printf("shuffle_msg_length = %d\n", config->shuffle_msg_length);
}
