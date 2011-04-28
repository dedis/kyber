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
#include <QFile>
#include <QString>
#include <QTime>
#include <QTimer>
#include <QByteArray>
#include <cstdio>
#include <cstring>

Handler::Handler(int node_id, int argc, char* argv[])
    : _node_id(node_id), _round(0),
      _maxRound(10), _wait(1000), _quiet(false){
    Q_UNUSED(argc);
    QByteArray data;
    int j = 1;
    for(int i = 1; argv[i]; ++i)
        if(strcmp(argv[i], "-f") == 0){
            QFile file(argv[++i]);
            if(!file.open(QIODevice::ReadOnly)){
                printf("Cannot open file %s\n", argv[i]);
                continue;
            }
            data = file.readAll();
        }else if(strcmp(argv[i], "-r") == 0)
            _maxRound = atoi(argv[++i]);
        else if(strcmp(argv[i], "-w") == 0)
            _wait = atoi(argv[++i]);
        else if(strcmp(argv[i], "-q") == 0)
            _quiet = true;
        else if(i != j)  // leave the unknown options there
            argv[j++] = argv[i];
    if(data.isNull()){
        QString str("Init node %1:");
        data = str.arg(_node_id).toUtf8();
        for(int i = 0; i < _node_id; ++i)
            data.append(";;;;;");
    }
    _queue.push_back(data);

    connect(qApp, SIGNAL(aboutToQuit()),
            this, SLOT(TearDown()));
}

void Handler::Start(){
    if(_wait > 0 && _round > 1){
        _timer = new QTimer(this);
        _timer->setInterval(_wait);
        connect(_timer, SIGNAL(timeout()),
                this, SLOT(MoreData()));
        _timer->start();
    }

    if(_queue.size() > 0){
        emit moreData(_queue.front());
        _queue.pop_front();
    }
}

void Handler::ShuffledData(QList<QByteArray> data){
    if(_quiet){
        printf("Round %d: %d messages\nSize:", _round, data.size());
        foreach(const QByteArray& byte_array, data)
            printf(" %d", byte_array.size());
        putchar('\n');
    }else{
        printf("======Round %2d======\n", _round);
        int i = 0;
        foreach(const QByteArray& byte_array, data)
            if(!byte_array.isEmpty())
                printf("%d: %s\n", i++, byte_array.data());
        printf("====================\n");
    }

    if(_queue.size() > 0){
        emit moreData(_queue.front());
        _queue.pop_front();
    }
    if(++_round >= _maxRound){
        printf("%d queued messages dropped\n", _queue.size());

        emit finish();
        // exit gracefully: let the main loop evacuate the event queue first
        QTimer::singleShot(0, qApp, SLOT(quit()));
    }
}

void Handler::ProtocolStarted(int round){
    Q_ASSERT(_round == round);
    if(round == 0)
        _time.start();
}

void Handler::MoreData(){
    QString data("Node %1 at round %2.");
    _queue.push_back(data.arg(_node_id).arg(_round).toUtf8());
}

void Handler::TearDown(){
    if(_time.isValid()){
        int msec = _time.elapsed();
        printf("Time elapsed: %d.%03d seconds\n",
               msec / 1000, msec % 1000);
    }
}
