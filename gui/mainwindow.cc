/* gui/mainwindow.cc
   Main window for GUI.

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

#include <QtGui>

#include "mainwindow.h"

namespace {

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
 
 private:
  QList<QString> message_queue_;
};

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
                                       Qt::Orientation orientation, int role) {
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

  endInsertRows();
  return true;
}

bool MessageTableModel::removeRows(int position, int rows,
                                   const QModelIndex &index = QModelIndex());
  Q_UNUSED(index);
  beginRemoveRows(QModelIndex(), position, position+rows-1);

  endRemoveRows();
  return true;
}

namespace Dissent {

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent) {
  setupUi(this);

  // configure slot-signals
  connect(inputLineEdit, SIGNAL(returnPressed()), sendButton, SLOT(clicked())); 
}

void MainWindow::on_inputLineEdit_textChanged() {
  sendButton->setEnabled(!inputLineEdit->text().isEmpty());
}

void MainWindow::on_sendButton_clicked() {
  QString input = sendButton->text();
  if (!input.isEmpty()) {
    message_queue_.push_back(input);
  }
}

}


