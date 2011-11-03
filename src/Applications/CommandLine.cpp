#include <qcoreapplication.h>
#include "CommandLine.hpp"

namespace Dissent {
namespace Applications {
  CommandLine::CommandLine(const QList<QSharedPointer<Node> > &nodes) :
    _nodes(nodes),
    _current_node(0),
    _running(false),
    _notify(STDIN_FILENO, QSocketNotifier::Read),
    _qtin(stdin, QIODevice::ReadOnly)
  {
  }

  CommandLine::~CommandLine()
  {
    Stop();
  }

  void CommandLine::Start()
  {
    if(_running) {
      return;
    }

    _running = true;

    QObject::connect(&_notify, SIGNAL(activated(int)), this, SLOT(Read()));
    _notify.setEnabled(true);

    _qtout << "Dissent Console";
    PrintCommandLine();
  }

  void CommandLine::Stop()
  {
    if(!_running) {
      return;
    }

    _running = false;

    _notify.setEnabled(false);
    QObject::disconnect(&_notify, SIGNAL(activated(int)), this, SLOT(Read()));

    _qtout << endl << "Goodbye" << endl << endl;
  }

  void CommandLine::PrintCommandLine()
  {
    _qtout << endl << "Command: ";
    _qtout.flush();
  }

  void CommandLine::HandleData(const QByteArray &data, ISender *from)
  {
    ConsoleSink::HandleData(data, from);
    PrintCommandLine();
  }

  void CommandLine::Ready()
  {
    _qtout << endl << "System operational, begin sending messages...";
    PrintCommandLine();
  }

  void CommandLine::Read()
  {
    QString msg = _qtin.readLine();
    QString cmd = msg;
    int idx = msg.indexOf(" ");
    if(idx > 0) {
      cmd = msg.left(idx);
      msg = msg.right(msg.size() - idx);
    }
    cmd.toLower();

    if(cmd == "exit") {
      QCoreApplication::exit();
      return;
    } else if(cmd == "help") {
      _qtout << "Commands: " << endl;
      _qtout << "\tcurrent - print the index of the current node" << endl;
      _qtout << "\tselect index - use the node at index to execute command" << endl;
      _qtout << "\tsend \"msg\" - send \"msg\" to Dissent round" << endl;
      _qtout << "\texit - kill the node and exit to command line" << endl;
    } else if(cmd == "current") {
      _qtout << "Current node: " << QString::number(_current_node) << endl;
    } else if(cmd == "select") {
      bool valid;
      int current = msg.toInt(&valid);
      if(valid) {
        _current_node = current;
        _qtout << endl << "New current node: " << msg;
      } else {
        _qtout << endl << "Invalid entry: " << msg;
      }
    } else if(cmd == "send") {
      QSharedPointer<Session> session = _nodes[_current_node]->session;
      if(session.isNull()) {
        _qtout << endl << "No session set, try again later." << endl;
        return;
      }
      session->Send(msg.toUtf8());
    } else if(cmd == "") {
    } else {
      _qtout << "Unknown command, " << cmd << ", type help for more " <<
        "information." << endl;
    }

    PrintCommandLine();
  }
}
}
