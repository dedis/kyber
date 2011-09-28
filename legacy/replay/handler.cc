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

#include <QByteArray>
#include <QCoreApplication>
#include <QFile>
#include <QRegExp>
#include <QString>
#include <QTime>
#include <QTimer>
#include <cstdio>
#include <cstring>
#include <cmath>

#include "QByteArrayUtil.hpp"
#include "config.hpp"

QRegExp Handler::LogRE("(\\d+):(\\d+):(\\d+)\\s*<([^>]+)>\\s*(.+)");

Handler::Handler(const Dissent::Configuration& config, int argc, char* argv[])
    : _config(config), _node_id(config.my_node_id), _message_time(-1){
    Q_UNUSED(argc);
    QByteArray data;
    int j = 1;
    for(int i = 1; argv[i]; ++i)
        if(strcmp(argv[i], "-f") == 0){
            _ifile.reset(new QFile(argv[++i]));
            if(!_ifile->open(QIODevice::ReadOnly)){
                printf("Cannot open file %s\n", argv[i]);
                continue;
            }
            _istream.setDevice(_ifile.data());
        }else if(i != j)  // leave the unknown options there
            argv[j++] = argv[i];
    connect(qApp, SIGNAL(aboutToQuit()),
            this, SLOT(TearDown()));
}

void Handler::Start(){
    _time.start();

    setvbuf(stdout, NULL, _IOLBF, BUFSIZ);
}

void Handler::ShuffledData(QList<QByteArray> data){
    if(_message_time < 0){
        int init_timestamp;
        int node_id;
        bool r = GetNext(false, &init_timestamp, &node_id, &_next_message);
        Q_ASSERT_X(r, "Handler::Start", "No line in the script");
    
        int timestamp = init_timestamp;
        if(node_id != _node_id){
            r = GetNext(true, &timestamp, &node_id, &_next_message);
            Q_ASSERT_X(r, "Handler::Start", "No line for this client");
        }
    
        _num_nodes_done = 0;
        QTimer::singleShot((timestamp - init_timestamp) * 1000,
                           this, SLOT(MoreData()));
        _message_time = timestamp;
    }

    int i = 0;
    foreach(QByteArray ba, data){
        ++i;
        while(ba.size() > 0){
            int from_node = QByteArrayUtil::ExtractInt(true, &ba);
            int timestamp = QByteArrayUtil::ExtractInt(true, &ba);
            int data_len = QByteArrayUtil::ExtractInt(true, &ba);
            ba = ba.mid(data_len);

            if(from_node == _node_id && data_len > 0){
                int delay = _time.elapsed() - timestamp;
                Q_ASSERT(delay >= 0);
                _delays.push_back(delay);
            }

            if(data_len == 0)
                ++_num_nodes_done;
        }
    }
    if(_num_nodes_done == _config.num_nodes){
        emit finish();

        // exit gracefully: let the main loop evacuate the event queue first
        QTimer::singleShot(0, qApp, SLOT(quit()));
    }
}

void Handler::StepEnded(QString step_name){
    int msec = _time.elapsed();
    printf("%s: %d.%03d seconds\n",
           step_name.toUtf8().data(), msec / 1000, msec % 1000);
}

void Handler::MoreData(){
    QByteArray msg = _next_message.toUtf8();
    QByteArrayUtil::PrependInt(msg.size(), &msg);
    QByteArrayUtil::PrependInt(_time.elapsed(), &msg);
    QByteArrayUtil::PrependInt(_node_id, &msg);
    emit moreData(msg);

    int timestamp, node_id;
    if(GetNext(true, &timestamp, &node_id, &_next_message)){
        Q_ASSERT(timestamp >= _message_time);
        QTimer::singleShot((timestamp - _message_time) * 1000,
                           this, SLOT(MoreData()));
        _message_time = timestamp;
    }else{
        msg.clear();
        QByteArrayUtil::PrependInt(0, &msg);
        QByteArrayUtil::PrependInt(_time.elapsed(), &msg);
        QByteArrayUtil::PrependInt(_node_id, &msg);
        emit moreData(msg);
    }
}

void Handler::TearDown(){
    printf("delays:");
    foreach(int delay, _delays)
        printf(" %d.%03d", delay / 1000, delay % 1000);
    putchar('\n');
}

bool Handler::GetNext(bool only_mine,
                      int* timestamp, int* node_id, QString* message){
    while(!_istream.atEnd()){
        QString line = _istream.readLine();
        if(!LogRE.exactMatch(line))
            continue;

        QStringList split = LogRE.capturedTexts();
        Q_ASSERT(split.size() == 6);

        int node = split[4].toInt();
        if(only_mine && node != _node_id)
            continue;

        *timestamp = (split[1].toInt() * 60
                    + split[2].toInt()) * 60
                    + split[3].toInt();
        *node_id = node;
        *message = split[5];
        return true;
    }
    return false;
}
