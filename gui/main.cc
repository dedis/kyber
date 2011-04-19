/* gui/main.cc
   Main function for GUI

   Author: Fei Huang <felix.fei.huang@gmail.com>
 */
/* ====================================================================
 * Dissent: Accountable Group Anonymity
 * Copyright (c) 2010 Yale University.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to
 *
 *   Free Software Foundation, Inc.,
 *   51 Franklin Street, Fifth Floor,
 *   Boston, MA  02110-1301  USA
 */

#include <QApplication>

#include "config.hpp"
#include "crypto.hpp"
#include "node.hpp"

#include "mainwindow.h"

#define MAX_NODE_ID 3

// This function is written by Shu-Chun Weng
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
    config->shuffle_msg_length = 32;

    Dissent::NodeTopology tp1 = { 1, 2, -1};
    Dissent::NodeTopology tp2 = { 2, 3, 1};
    Dissent::NodeTopology tp3 = { 3, -1, 2};
    config->topology.clear();
    config->topology.push_back(tp1);
    config->topology.push_back(tp2);
    config->topology.push_back(tp3);
    config->my_position = node_id - 1;
    config->protocol_version = Dissent::Configuration::DISSENT_SHUFFLE_ONLY;
}

int main(int argc, char* argv[]){
    Q_ASSERT(argc > 1);
    bool ok = false;
    int node_id = QString(argv[1]).toInt(&ok);
    Q_ASSERT_X(ok, "main", "converting argv[1] to integer failed");
    Q_ASSERT(node_id >= 1 && node_id <= MAX_NODE_ID);

    Dissent::Crypto::GetInstance();
    QApplication app(argc, argv);
    Dissent::Configuration config;
    InitializeDummyConfig(node_id, &config);

    Dissent::Node node(config);
    int round_interval = 3000;
    Dissent::MainWindow *window = new Dissent::MainWindow(node_id, &node, 
                                                          round_interval);
    
    QObject::connect(
            &node, SIGNAL(shuffledDataReady(const QList<QByteArray>&)),
            window, SLOT(ShuffledData(const QList<QByteArray>&)));
    QObject::connect(
            window, SIGNAL(finish()),
            &node, SLOT(StopProtocol()));
    QObject::connect(
            window, SIGNAL(feedData(const QByteArray &)),
            &node, SLOT(EnterData(const QByteArray &)));
    window->Start();
    return app.exec();
}

