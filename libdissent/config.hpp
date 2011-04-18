/* libdissent/config.hpp
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
#ifndef _DISSENT_LIBDISSENT_CONFIG_HPP_
#define _DISSENT_LIBDISSENT_CONFIG_HPP_ 1
#include <QByteArray>
#include <QList>
#include <QMap>
#include <QSharedPointer>
#include <QString>

#include "dissent_global.hpp"
#include "crypto.hpp"

namespace Dissent{
// XXX(scw): don't export once Configuration::Serialize / Deserialize
//           are working
struct DISSENT_EXPORT NodeInfo{
    int node_id;
    QString addr;
    int port;
    PublicKey identity_pk;

    bool excluded;  // derived from NodeTopology
};

// A topology is an array of form:
//    { (NodeTopology){ node_id: 2, next_node_id:  3, prev_node_id: -1 },
//      (NodeTopology){ node_id: 3, next_node_id:  1, prev_node_id:  2 },
//      (NodeTopology){ node_id: 1, next_node_id: -1, prev_node_id:  3 } }
// XXX(scw): don't export once Configuration::Serialize / Deserialize
//           are working
struct DISSENT_EXPORT NodeTopology{
    int node_id;
    int next_node_id;
    int prev_node_id;
};

struct DISSENT_EXPORT Configuration{
    // private members
    int my_node_id;
    PrivateKey identity_sk;

    // private but identical on all nodes
    QMap<int, NodeInfo> nodes;

    // shared between all nodes, broadcast by the leader
    int num_nodes;
    int disposable_key_length;
    int shuffle_msg_length;

    QList<NodeTopology> topology;
    int my_position;  // my position in the topology

    enum ProtocolVersion{
        DISSENT_SHUFFLE_ONLY,
        DISSENT_VERSION_1,
        DISSENT_VERSION_2, DISSENT_VERSION_2P,
    } protocol_version;

    // Constructors.
    Configuration();
    Configuration(int argc, char* argv[]);

    // Serialize shared members of this object to a byte array.
    // Returns true if succeeded.
    bool Serialize(QByteArray* byte_array) const;

    // Update shared members of this object according to the byte array.
    // Returns true if succeeded.
    bool Deserialize(const QByteArray& byte_array);
};
}
#endif  // _DISSENT_LIBDISSENT_CONFIG_HPP_
// -*- vim:sw=4:expandtab:cindent:
