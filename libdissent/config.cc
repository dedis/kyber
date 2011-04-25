/* libdissent/config.cc
   Node configuration data definition.

   Author: Shu-Chun Weng <scweng _AT_ cs .DOT. yale *DOT* edu>
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
#include "config.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <QtCrypto>
#include <QFile>
#include <QIODevice>
#include <QList>
#include <QString>
#include <QTextStream>

#include "node_impl_bulk.hpp"  // for shuffle_msg_length

namespace Dissent{
void Usage(int argc, char* argv[]){
    Q_UNUSED(argc);
    printf("Usage: %s [options]\n"
           "  options:\n"
           "    -c file      load configuration from file\n"
           "    -h           display this help message\n"
           "    -n node_id\n"
           "    -s sk_file   private (secret) key file\n"
           , argv[0]);
    exit(0);
}

Configuration::Configuration()
    : my_node_id(-1),
      disposable_key_length(1024),
      my_position(-1),
      protocol_version(DISSENT_VERSION_1){
}

Configuration::Configuration(int argc, char* argv[])
    : my_node_id(-1),
      disposable_key_length(1024),
      my_position(-1),
      protocol_version(DISSENT_VERSION_1){
    for(int i = 1; i < argc; ++i){
        if(strcmp(argv[i], "-c") == 0)
            LoadFromFile(argv[++i]);
        else if(strcmp(argv[i], "-n") == 0)
            my_node_id = atoi(argv[++i]);
        else if(strcmp(argv[i], "-s") == 0){
            QCA::ConvertResult convert_result;
            QCA::PrivateKey sk = QCA::PrivateKey::fromPEMFile(
                    argv[++i],
                    QCA::SecureArray(), &convert_result);
            Q_ASSERT(convert_result == QCA::ConvertGood);
            Q_ASSERT(sk.isRSA());
            identity_sk = sk.toRSA();
        }else if(strcmp(argv[i], "-h") == 0)
            Usage(argc, argv);
    }

    if(my_node_id != -1){
        for(int i = 0; i < topology.size(); ++i)
            if(topology[i].node_id == my_node_id){
                my_position = i;
                break;
            }
        if(my_position == -1){
            printf("We (node id %d) don't belong to the network topology\n",
                   my_node_id);
            exit(0);
        }
    }

    if(!identity_sk.isNull()){
        switch(protocol_version){
            case DISSENT_SHUFFLE_ONLY:
                Q_ASSERT(shuffle_msg_length > 0);
                break;
            case DISSENT_VERSION_1: {
                    QByteArray ba("");
                    Dissent::BulkSend::MessageDescriptor desc(this);
                    desc.Initialize(ba);
                    desc.Serialize(&ba);
                    shuffle_msg_length = ba.size();
                    break;
                }
            case DISSENT_VERSION_2:
            case DISSENT_VERSION_2P:
                printf("Warning: shuffle_msg_length not known for"
                       " this protocol yet\n");
                break;
        }
    }
}

bool Configuration::Serialize(QByteArray* byte_array) const{
    byte_array->clear();
    // not implemented yet
    // return false;
    // XXX(fh): always return true to bypass serialization
    return true;
}

bool Configuration::Deserialize(const QByteArray& byte_array){
    // not implemented yet
    // return false;
    Q_UNUSED(byte_array);
    // XXX(fh): always return true to bypass deserialization
    return true;
}

bool Configuration::LoadFromFile(const QString& filename){
    QFile file(filename);
    if(!file.open(QIODevice::ReadOnly | QIODevice::Text))
        return false;

#define BAD_LINE(R) do{                       \
        printf("Bad config line %s:%d: %s\n", \
               filename.toUtf8().constData(), \
               lineno, R);                    \
        goto parse_next;                      \
    }while(0)
    QTextStream in(&file);
    int lineno = 1;
    for(QString line = in.readLine();
        !line.isNull();
        line = in.readLine(), ++lineno){
        int comments = line.indexOf('#');
        if(comments >= 0)
            line = line.left(comments);
        int equal_sign = line.indexOf('=');
        if(equal_sign < 0)
            continue;
        QString key = line.left(equal_sign);
        QString value = line.mid(equal_sign + 1);

        if(key.startsWith("node")){
            bool ok;
            int the_node_id = key.mid(4).toInt(&ok);
            if(!ok)
                BAD_LINE("node without number");
            QList<QString> list = value.split(':');
            if(list.size() != 3)
                BAD_LINE("node line should be keyfile:host:port");

            QCA::ConvertResult convert_result;
            QCA::PublicKey pk = QCA::PublicKey::fromPEMFile(
                    list[0], &convert_result);
            if(convert_result != QCA::ConvertGood)
                BAD_LINE("Error reading public key file");
            if(!pk.isRSA())
                BAD_LINE("Not an RSA public key");
            int port = list[2].toInt(&ok);
            if(!ok)
                BAD_LINE("node line should be keyfile:host:port");

            NodeInfo& info = nodes[the_node_id];
            info.node_id = the_node_id;
            info.addr = list[1];
            info.port = port;
            info.identity_pk = pk.toRSA();
            info.excluded = false;

            int prev_node_id = -1;
            if(topology.size() > 0){
                prev_node_id = topology.back().node_id;
                topology.back().next_node_id = the_node_id;
            }
            NodeTopology top = { the_node_id, -1, prev_node_id };
            topology.push_back(top);
        }else if(key == "disposable_key_length"){
            bool ok;
            int len = value.toInt(&ok);
            if(!ok)
                BAD_LINE("cannot parse disposable_key_length");
            disposable_key_length = len;
        }else if(key == "shuffle_msg_length"){
            bool ok;
            int len = value.toInt(&ok);
            if(!ok)
                BAD_LINE("cannot parse shuffle_msg_length");
            shuffle_msg_length = len;
        }else if(key == "protocol_version"){
            if(value == "shuffle_only")
                protocol_version = DISSENT_SHUFFLE_ONLY;
            else if(value == "version_1")
                protocol_version = DISSENT_VERSION_1;
            else if(value == "version_2")
                protocol_version = DISSENT_VERSION_2;
            else if(value == "version_2p")
                protocol_version = DISSENT_VERSION_2P;
            else
                BAD_LINE("Unknown version");
        }else
            BAD_LINE("Unrecognized option");
#undef BAD_LINE
parse_next:
        (void) 0;
    }

    num_nodes = topology.size();
    return true;
}
}
// -*- vim:sw=4:expandtab:cindent:
