# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'uDissent.ui'
#
# Created by: PyQt4 UI code generator 4.7.3
#
# WARNING! All changes made in this file will be lost!

from PyQt4 import QtCore, QtGui
from PyQt4.Qt import QString
import sys
import net
import socket

class Ui_uDissentWindow(object):
    def setupUi(self, uDissentWindow):
        uDissentWindow.setObjectName("uDissentWindow")
        uDissentWindow.resize(752, 600)
        self.centralwidget = QtGui.QWidget(uDissentWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.horizontalLayoutWidget = QtGui.QWidget(self.centralwidget)
        self.horizontalLayoutWidget.setGeometry(QtCore.QRect(0, 0, 351, 41))
        self.horizontalLayoutWidget.setObjectName("horizontalLayoutWidget")
        self.horizontalLayout = QtGui.QHBoxLayout(self.horizontalLayoutWidget)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.inviteButton = QtGui.QPushButton(self.horizontalLayoutWidget)
        self.inviteButton.setObjectName("inviteButton")
        self.horizontalLayout.addWidget(self.inviteButton)
        self.inviteEdit = QtGui.QLineEdit(self.horizontalLayoutWidget)
        self.inviteEdit.setObjectName("inviteEdit")
        self.horizontalLayout.addWidget(self.inviteEdit)
        self.horizontalLayoutWidget_2 = QtGui.QWidget(self.centralwidget)
        self.horizontalLayoutWidget_2.setGeometry(QtCore.QRect(0, 30, 351, 41))
        self.horizontalLayoutWidget_2.setObjectName("horizontalLayoutWidget_2")
        self.horizontalLayout_2 = QtGui.QHBoxLayout(self.horizontalLayoutWidget_2)
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.saveButton = QtGui.QPushButton(self.horizontalLayoutWidget_2)
        self.saveButton.setObjectName("saveButton")
        self.horizontalLayout_2.addWidget(self.saveButton)
        self.saveEdit = QtGui.QLineEdit(self.horizontalLayoutWidget_2)
        self.saveEdit.setObjectName("saveEdit")
        self.horizontalLayout_2.addWidget(self.saveEdit)
        self.verticalLayoutWidget = QtGui.QWidget(self.centralwidget)
        self.verticalLayoutWidget.setGeometry(QtCore.QRect(0, 60, 531, 491))
        self.verticalLayoutWidget.setObjectName("verticalLayoutWidget")
        self.verticalLayout = QtGui.QVBoxLayout(self.verticalLayoutWidget)
        self.verticalLayout.setObjectName("verticalLayout")
        self.horizontalLayout_3 = QtGui.QHBoxLayout()
        self.horizontalLayout_3.setContentsMargins(-1, -1, 0, 0)
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        self.startButton = QtGui.QPushButton(self.verticalLayoutWidget)
        self.startButton.setObjectName("startButton")
        self.horizontalLayout_3.addWidget(self.startButton)
        self.chatEdit = QtGui.QLineEdit(self.verticalLayoutWidget)
        self.chatEdit.setObjectName("chatEdit")
        self.horizontalLayout_3.addWidget(self.chatEdit)
        self.verticalLayout.addLayout(self.horizontalLayout_3)
        self.label = QtGui.QLabel(self.verticalLayoutWidget)
        self.label.setObjectName("label")
        self.verticalLayout.addWidget(self.label)
        self.pubkeyEdit = QtGui.QTextEdit(self.verticalLayoutWidget)
        self.pubkeyEdit.setObjectName("pubkeyEdit")
        self.verticalLayout.addWidget(self.pubkeyEdit)
        self.label_2 = QtGui.QLabel(self.verticalLayoutWidget)
        self.label_2.setObjectName("label_2")
        self.verticalLayout.addWidget(self.label_2)
        self.debugEdit = QtGui.QTextEdit(self.verticalLayoutWidget)
        self.debugEdit.setObjectName("debugEdit")
        self.verticalLayout.addWidget(self.debugEdit)
        self.verticalLayoutWidget_2 = QtGui.QWidget(self.centralwidget)
        self.verticalLayoutWidget_2.setGeometry(QtCore.QRect(350, 0, 181, 70))
        self.verticalLayoutWidget_2.setObjectName("verticalLayoutWidget_2")
        self.verticalLayout_2 = QtGui.QVBoxLayout(self.verticalLayoutWidget_2)
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.dropButton = QtGui.QPushButton(self.verticalLayoutWidget_2)
        self.dropButton.setObjectName("dropButton")
        self.verticalLayout_2.addWidget(self.dropButton)
        self.fileButton = QtGui.QPushButton(self.verticalLayoutWidget_2)
        self.fileButton.setObjectName("fileButton")
        self.verticalLayout_2.addWidget(self.fileButton)
        self.verticalLayoutWidget_3 = QtGui.QWidget(self.centralwidget)
        self.verticalLayoutWidget_3.setGeometry(QtCore.QRect(540, 0, 211, 551))
        self.verticalLayoutWidget_3.setObjectName("verticalLayoutWidget_3")
        self.verticalLayout_3 = QtGui.QVBoxLayout(self.verticalLayoutWidget_3)
        self.verticalLayout_3.setObjectName("verticalLayout_3")
        self.label_3 = QtGui.QLabel(self.verticalLayoutWidget_3)
        self.label_3.setObjectName("label_3")
        self.verticalLayout_3.addWidget(self.label_3)
        self.peerList = QtGui.QListWidget(self.verticalLayoutWidget_3)
        self.peerList.setObjectName("peerList")
        self.peerList.setSelectionMode(QtGui.QAbstractItemView.MultiSelection)
        self.verticalLayout_3.addWidget(self.peerList)
        self.bootButton = QtGui.QPushButton(self.verticalLayoutWidget_3)
        self.bootButton.setObjectName("bootButton")
        self.verticalLayout_3.addWidget(self.bootButton)
        uDissentWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtGui.QMenuBar(uDissentWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 752, 22))
        self.menubar.setObjectName("menubar")
        uDissentWindow.setMenuBar(self.menubar)
        self.statusbar = QtGui.QStatusBar(uDissentWindow)
        self.statusbar.setObjectName("statusbar")
        uDissentWindow.setStatusBar(self.statusbar)

        self.retranslateUi(uDissentWindow)
        self.net = net.Net(self)
        self.net.start()

        # make this button temporarily force debug messages for testing
        QtCore.QObject.connect(self.inviteButton, QtCore.SIGNAL("clicked()"), self.invitePressed)
        QtCore.QObject.connect(self.saveButton, QtCore.SIGNAL("clicked()"), self.savePressed)
        QtCore.QObject.connect(self.dropButton, QtCore.SIGNAL("clicked()"), self.dropPressed)
        QtCore.QObject.connect(self.bootButton, QtCore.SIGNAL("clicked()"), self.bootPressed)
        QtCore.QObject.connect(self.startButton, QtCore.SIGNAL("clicked()"), self.startPressed)
        QtCore.QObject.connect(self.fileButton, QtCore.SIGNAL("clicked()"), self.showDialog)
        QtCore.QMetaObject.connectSlotsByName(uDissentWindow)
        self.add_nodes()
        QtCore.QObject.connect(self.net, QtCore.SIGNAL("messageReceived(QString)"), self.displayMessage)
        QtCore.QObject.connect(self.net, QtCore.SIGNAL("updatePeers()"), self.add_nodes)
        QtCore.QObject.connect(self.net, QtCore.SIGNAL("getSharedFilename()"), self.set_shared_filename)
        QtCore.QObject.connect(self.net, QtCore.SIGNAL("getDistrustedPeers()"), self.get_distrusted_peers)

    def retranslateUi(self, uDissentWindow):
        uDissentWindow.setWindowTitle(QtGui.QApplication.translate("uDissentWindow", "uDissent", None, QtGui.QApplication.UnicodeUTF8))
        self.inviteButton.setText(QtGui.QApplication.translate("uDissentWindow", "Invite", None, QtGui.QApplication.UnicodeUTF8))
        self.inviteEdit.setText(QtGui.QApplication.translate("uDissentWindow", "IP:PORT", None, QtGui.QApplication.UnicodeUTF8))
        self.saveButton.setText(QtGui.QApplication.translate("uDissentWindow", "Save Key", None, QtGui.QApplication.UnicodeUTF8))
        self.saveEdit.setText(QtGui.QApplication.translate("uDissentWindow", "IP:PORT", None, QtGui.QApplication.UnicodeUTF8))
        self.startButton.setText(QtGui.QApplication.translate("uDissentWindow", "Start Round", None, QtGui.QApplication.UnicodeUTF8))
        self.chatEdit.setText(QtGui.QApplication.translate("uDissentWindow", "Path to data file you wish to distribute...", None, QtGui.QApplication.UnicodeUTF8))
        self.label.setText(QtGui.QApplication.translate("uDissentWindow", "Paste the public key here to save it...", None, QtGui.QApplication.UnicodeUTF8))
        self.label_2.setText(QtGui.QApplication.translate("uDissentWindow", "Debug", None, QtGui.QApplication.UnicodeUTF8))
        self.dropButton.setText(QtGui.QApplication.translate("uDissentWindow", "Drop out of Dissent", None, QtGui.QApplication.UnicodeUTF8))
        self.fileButton.setText(QtGui.QApplication.translate("uDissentWindow", "Choose File to Send...", None, QtGui.QApplication.UnicodeUTF8))
        self.label_3.setText(QtGui.QApplication.translate("uDissentWindow", "Nodes in my Network", None, QtGui.QApplication.UnicodeUTF8))
        self.bootButton.setText(QtGui.QApplication.translate("uDissentWindow", "Boot Selected Node", None, QtGui.QApplication.UnicodeUTF8))

    # display any messages populated up to GUI
    def displayMessage(self, msg):
        self.debugEdit.append("<b>Net</b>: " + msg)

    def savePressed(self):
        (ip, port) = str(self.saveEdit.text()).split(':')
        ip = socket.gethostbyname(ip)
        pubkey = str(self.pubkeyEdit.toPlainText())
        self.net.save_peer_key(ip, port, pubkey)
        self.displayMessage("saved!")

    def dropPressed(self):
        self.net.drop_out()

    def showDialog(self):
        filename = QtGui.QFileDialog.getOpenFileName(self.centralwidget, 'Choose File', '/home')
        self.chatEdit.setText(filename)

    def set_shared_filename(self):
        text = str(self.chatEdit.text())
        self.net.shared_filename = text
    
    def get_distrusted_peers(self):
        nodes = self.peerList.selectedItems()
        peers = []
        for index in range(0, len(nodes)):
            peer = str(nodes[index].text())
            (ip, port) = peer.split(':')
            ip = socket.gethostbyname(ip)
            peers.append((ip, port))
        self.net.distrusted_peers = peers

    # add peers from net class to list
    def add_nodes(self):
        self.peerList.clear()
        peers = self.net.nodes
        for peer in peers:
            self.peerList.addItem(QString(socket.gethostbyaddr(peer[0])[0] + ":" + str(peer[1])))
    
    def invitePressed(self):
        peer = str(self.inviteEdit.text())
        (ip, port) = peer.split(':')
        ip = socket.gethostbyname(ip)
        self.net.invite_peer(ip, int(port))

    def bootPressed(self):
        node = self.peerList.selectedItems()
        if len(node) > 2:
            self.displayMessage("Please select only one node please")
        node = str(node[0].text())
        (ip, port) = node.split(':')
        ip = socket.gethostbyname(ip)
        self.net.expel_peer(ip, int(port))

    def startPressed(self):
        self.net.initiate_round()

class Main(QtGui.QMainWindow):
    def __init__(self):
        QtGui.QMainWindow.__init__(self)

        self.ui=Ui_uDissentWindow()
        self.ui.setupUi(self)

def main():
    app=QtGui.QApplication(sys.argv)
    window=Main()
    window.show()
    
    # shutdown the server upon exit
    app.connect(app, QtCore.SIGNAL("lastWindowClosed()"), window.ui.net.server.shutdown)
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
