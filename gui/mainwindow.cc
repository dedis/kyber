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
#include "messagetablemodel.h"

namespace Dissent {

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent) {
  setupUi(this);

  queued_message_model_ = new MessageTableModel;
  queuedMsgView->setModel(queued_message_model_);
  queuedMsgView->horizontalHeader()->setStretchLastSection(true);
  queuedMsgView->verticalHeader()->hide();
  
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

void MainWindow::SubmitMessage(const QString &msg) {
  if (msg.isEmpty())
    return;

  int size = queued_message_model_->queue_size();
  queued_message_model_->insertRows(size, 1, QModelIndex());
  QModelIndex index = queued_message_model_->index(size, 0, QModelIndex());
  queued_message_model_->setData(index, msg, Qt::EditRole);

  inputLineEdit->clear();
}

}


