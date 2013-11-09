#include <unistd.h>
#include <qcoreapplication.h>

#include "CommandLine.hpp"
#include "Node.hpp"

namespace Dissent {
namespace Applications {
  CommandLine::CommandLine(const QList<QSharedPointer<Node> > &nodes) :
    m_nodes(nodes),
    m_current_node(0),
    m_running(false),
    m_notify(STDIN_FILENO, QSocketNotifier::Read),
    m_qtin(stdin, QIODevice::ReadOnly)
  {
  }

  CommandLine::~CommandLine()
  {
    Stop();
  }

  void CommandLine::Start()
  {
    if(m_running) {
      return;
    }

    m_running = true;

    QObject::connect(&m_notify, SIGNAL(activated(int)), this, SLOT(Read()));
    m_notify.setEnabled(true);

    m_qtout << "Dissent Console";
    PrintCommandLine();
  }

  void CommandLine::Stop()
  {
    if(!m_running) {
      return;
    }

    m_running = false;

    m_notify.setEnabled(false);
    QObject::disconnect(&m_notify, SIGNAL(activated(int)), this, SLOT(Read()));

    m_qtout << endl << "Goodbye" << endl << endl;
  }

  void CommandLine::PrintCommandLine()
  {
    m_qtout << endl << "Command: ";
    m_qtout.flush();
  }

  void CommandLine::HandleData(const QSharedPointer<ISender> &from,
      const QByteArray &data)
  {
    ConsoleSink::HandleData(from, data);
    PrintCommandLine();
  }

  void CommandLine::Read()
  {
    QString msg = m_qtin.readLine();
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
      m_qtout << "Commands: " << endl;
      m_qtout << "\tcurrent - print the index of the current node" << endl;
      m_qtout << "\tselect index - use the node at index to execute command" << endl;
      m_qtout << "\tsend \"msg\" - send \"msg\" to Dissent round" << endl;
      m_qtout << "\texit - kill the node and exit to command line" << endl;
    } else if(cmd == "current") {
      m_qtout << "Current node: " << QString::number(m_current_node) << endl;
    } else if(cmd == "select") {
      bool valid;
      int current = msg.toInt(&valid);
      
      if(valid && current < m_nodes.count()) {
        m_current_node = current;
        m_qtout << endl << "New current node: " << msg;
      } else {
        m_qtout << endl << "Invalid entry: " << msg;
      }
    } else if(cmd == "send") {
      m_nodes[m_current_node]->GetSession()->Send(msg.toUtf8());
    } else if(cmd == "") {
    } else {
      m_qtout << "Unknown command, " << cmd << ", type help for more " <<
        "information." << endl;
    }

    PrintCommandLine();
  }
}
}
