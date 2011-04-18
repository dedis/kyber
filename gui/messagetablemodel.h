/* gui/messagetablemodel.cc
   Model for QueuedMessageTableView

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

#include <QAbstractTableModel>
#include <QList>
#include <QString>

namespace Dissent {

class MessageTableModel : public QAbstractTableModel {
  Q_OBJECT

 public:
  MessageTableModel(QObject *parent = 0);

  int rowCount(const QModelIndex &parent) const;
  int columnCount(const QModelIndex &parent) const;
  QVariant data(const QModelIndex &index, int role) const;
  QVariant headerData(int section, Qt::Orientation orientation, int role) const;
  bool insertRows(int position, int rows, 
                  const QModelIndex &index = QModelIndex());
  bool removeRows(int position, int rows,
                  const QModelIndex &index = QModelIndex());
  bool setData(const QModelIndex &index, const QVariant &value, int role);
  QList<QString> message_queue() const; 
  int queue_size() const;
  
 private:
  QList<QString> message_queue_;
};

}

