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

#include "messagetablemodel.h"

namespace Dissent {

MessageTableModel::MessageTableModel(QObject *parent) 
  : QAbstractTableModel(parent) {}
  
int MessageTableModel::rowCount(const QModelIndex &parent) const {
  Q_UNUSED(parent);
  return message_queue_.size();
}

int MessageTableModel::columnCount(const QModelIndex &parent) const {
  Q_UNUSED(parent);
  return 1;
}

QVariant MessageTableModel::data(const QModelIndex &index, int role) const {
  if (!index.isValid()) 
    return QVariant();

  if (index.row() >= message_queue_.size() || index.row() < 0) 
    return QVariant();

  if (role == Qt::DisplayRole) {
    return message_queue_[index.row()];
  }

  return QVariant();
}

QVariant MessageTableModel::headerData(int section, 
                            Qt::Orientation orientation, int role) const {
  if (role != Qt::DisplayRole)
    return QVariant();

  if (orientation == Qt::Horizontal) {
    if (section == 0)
      return tr("Queued Messages");
  }

  return QVariant();
}

bool MessageTableModel::insertRows(int position, int rows, 
                                   const QModelIndex &index) {
  Q_UNUSED(index);
  beginInsertRows(QModelIndex(), position, position+rows-1);

  for (int row = 0; row < rows; ++row) {
    message_queue_.insert(position, QString("None..."));
  }

  endInsertRows();
  return true;
}

bool MessageTableModel::removeRows(int position, int rows,
                                   const QModelIndex &index) {
  Q_UNUSED(index);
  beginRemoveRows(QModelIndex(), position, position+rows-1);

  for (int row = 0; row < rows; ++row) {
    message_queue_.removeAt(position);
  }

  endRemoveRows();
  return true;
}

bool MessageTableModel::setData(const QModelIndex &index, 
                                const QVariant &value, int role) {
  if (index.isValid() && role == Qt::EditRole) {
    int row = index.row();
    QString str = message_queue_.value(row);
    if (index.column() == 0) {
      str = value.toString();
    } else {
      return false;
    }
    message_queue_.replace(row, str);
    emit(dataChanged(index, index));
    return true;
  }              
  return false;
}

QList<QString> MessageTableModel::message_queue() const {
  return message_queue_;
}

int MessageTableModel::queue_size() const {
  return message_queue_.size();
}

}

