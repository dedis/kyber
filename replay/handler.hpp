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
#include <QFile>
#include <QList>
#include <QRegExp>
#include <QScopedPointer>
#include <QString>
#include <QTime>

#include "network.hpp"

namespace Dissent{
    class Configuration;
}
class Handler : public QObject{
  Q_OBJECT
  public:
    Handler(const Dissent::Configuration& config, int argc, char* argv[]);

  signals:
    void finish();
    void moreData(QByteArray data);

  public slots:
    void Start();
    void ShuffledData(QList<QByteArray> data);
    void StepEnded(QString step_name);

  protected slots:
    void MoreData();
    void TearDown();

  protected:
    bool GetNext(bool only_mine,
                 int* timestamp, int* node_id, QString* message);

    const Dissent::Configuration& _config;
    int _node_id;

    QTextStream _istream;
    QScopedPointer<QFile> _ifile;
    QString _next_message;
    int _message_time;

    QTime _time;
    QList<int> _delays;
    int _num_nodes_done;

    static QRegExp LogRE;
};
#endif  // _DISSENT_CLI_HANDLER_HPP_
