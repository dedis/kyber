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

#include "mainwindow.h"

#include <QtGui>

#include "node.hpp"
#include "messagetablemodel.h"

namespace Dissent {

MainWindow::MainWindow(int node_id, Node *node, int interval, QWidget *parent) 
  : QMainWindow(parent), node_id_(node_id), node_(node), 
    round_interval_(interval), round_(0) {
  setupUi(this);

  queued_message_model_ = new MessageTableModel;
  queuedMsgView->setModel(queued_message_model_);
  queuedMsgView->horizontalHeader()->setStretchLastSection(true);
  queuedMsgView->verticalHeader()->hide();
}

void MainWindow::Start() {
  this->show();
  QTimer::singleShot(0, node_, SLOT(StartProtocol()));
  QTimer::singleShot(10, this, SLOT(FeedData()));
}

void MainWindow::ShuffledData(const QList<QByteArray> &data) {
  output_lock_.lock();
  foreach (const QByteArray &bytearray, data) {
    PrintLine(bytearray.data());
  }
  PrintLine("------------------------------------------");
  output_lock_.unlock();
  ++round_;
  emit finish();
  // restart the protocol
  QTimer::singleShot(round_interval_, node_, SLOT(StartProtocol()));
  QTimer::singleShot(round_interval_ + 10, this, SLOT(FeedData()));
}

void MainWindow::FeedData() {
  QString message = "";

  if (queued_message_model_->queue_size() > 0) {
    message = queued_message_model_->message_queue()[0];
    queued_message_model_->removeRows(0, 1, QModelIndex());
  }
  emit feedData(message.toUtf8());
}

void MainWindow::on_inputLineEdit_textChanged() {
  sendButton->setEnabled(!inputLineEdit->text().isEmpty());
}

void MainWindow::on_inputLineEdit_returnPressed() {
  SubmitMessage(inputLineEdit->text());
}

void MainWindow::on_sendButton_clicked() {
  SubmitMessage(inputLineEdit->text());
}

void MainWindow::on_clearButton_clicked() {
  outputTextEdit->clear();
}

void MainWindow::SubmitMessage(const QString &message) {
  if (message.isEmpty())
    return;

  int size = queued_message_model_->queue_size();
  queued_message_model_->insertRows(size, 1, QModelIndex());
  QModelIndex index = queued_message_model_->index(size, 0, QModelIndex());
  queued_message_model_->setData(index, message, Qt::EditRole);

  inputLineEdit->clear();
}

void MainWindow::PrintLine(const QString &message) {
  if (message.isEmpty())
    return;

  outputTextEdit->append(message);
}

}


