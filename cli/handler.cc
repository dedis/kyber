/* cli/handler.cc
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

#include "handler.hpp"

#include <QCoreApplication>
#include <QString>
#include <QTimer>
#include <QByteArray>
#include <cstdio>

void Handler::RunNode1(){
    printf("Node 1 running\n");
    _network->ResetSession(0x5269);
    _network->Send(2, "How are you, 2?");
    _network->Send(3, "Not much!");

    _network->Broadcast("I AM LOUD AND ANONYING.");

    _network->StartIncomingNetwork();
}

void Handler::RunNode2(){
    printf("Node 2 running\n");
    _network->ResetSession(0x5269);
    _network->Send(3, "How is it going, 3?");
    _network->Send(1, "OK.");

    _network->StartIncomingNetwork();
}

void Handler::RunNode3(){
    printf("Node 3 running\n");
    _network->ResetSession(0x5269);
    _network->Send(1, "Whazzup, 1?");
    _network->Send(2, "Could be worse.");

    _network->StartIncomingNetwork();
}

void Handler::ReadMsg(int from_node_id){
    QByteArray byte_array;
    while(_network->Read(from_node_id, &byte_array) != 0){
        printf("%d <Node%d> %s\n", _node_id, from_node_id,
               (char*) byte_array.data());
    }
}

void Handler::ShuffledData(const QList<QByteArray>& data){
    int i = 0;
    foreach(const QByteArray& byte_array, data){
        printf("=====%d=====\n", i++);
        printf("%s\n", byte_array.data());
    }

    if(round++ == 0){
        QString data("Do you know that I am node %1?");
        emit moreData(data.arg(_node_id).toUtf8());
    }else{
        emit finish();
        QTimer::singleShot(1000, qApp, SLOT(quit()));
    }
}
