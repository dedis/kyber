/* cli/handler.hpp
   cli event handler

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

#ifndef _DISSENT_CLI_HANDLER_HPP_
#define _DISSENT_CLI_HANDLER_HPP_ 1
#include <QObject>
#include <QByteArray>
#include <QList>

#include "network.hpp"

class Handler : public QObject{
  Q_OBJECT
  public:
    Handler(int node_id)
        : _node_id(node_id), round(0){
    }

    void SetNetwork(Dissent::Network* network){
        _network = network;

        connect(network, SIGNAL(readyRead(int)),
                this, SLOT(ReadMsg(int)));
    }

  signals:
    void finish();
    void moreData(QByteArray data);

  public slots:
    void ReadMsg(int from_node_id);

    void ShuffledData(QList<QByteArray> data);

  protected:
    int _node_id;
    Dissent::Network* _network;

    int round;
};
#endif  // _DISSENT_CLI_HANDLER_HPP_
