/* gui/mainwindow.h
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

#ifndef _DISSENT_GUI_MAINWINDOW_H_
#define _DISSENT_GUI_MAINWINDOW_H_

#include <QDialog>

#include "ui_mainwindow.h"

namespace Dissent {

class MainWindow : public QMainWindow, public Ui::MainWindow {
  Q_OBJECT

 public:
  MainWindow(QWidget *parent = 0);

 private slots:
  void on_inputLineEdit_textChanged();
};

}

#endif
