#ifndef DISSENT_APPLICATIONS_COMMAND_LINE_H_GUARD
#define DISSENT_APPLICATIONS_COMMAND_LINE_H_GUARD

#include <QList>
#include <QObject>
#include <QSharedPointer>
#include <QSocketNotifier>
#include <QTextStream>

#include "ConsoleSink.hpp"
#include "Node.hpp"

namespace Dissent {
namespace Applications {
  /**
   * Allows for Asynchronous access to the commandline for input and output
   * purposes.  Useful for console applications.
   */
  class CommandLine : public QObject, public ConsoleSink {
    Q_OBJECT

    public:
      /**
       * Constructor
       * @param nodes the set of nodes running in this process
       */
      CommandLine(const QList<QSharedPointer<Node> > &nodes);

      virtual ~CommandLine();

      /**
       * Start the command line services
       */
      void Start();

      /**
       * Stop the commmand line services
       */
      void Stop();

      /**
       * A sink input to print data to the console in a pretty way
       * @param data incoming data
       * @param from the sender of the data
       */
      virtual void HandleData(const QByteArray &data, ISender *from);

    public slots:
      /**
       * Called when commands for sending data can be executed.
       */
      void Ready();

    private slots:
      /**
       * Called when there is input on stdin
       */
      void Read();

    protected:
      void PrintCommandLine();
      const QList<QSharedPointer<Node> > _nodes;
      int _current_node;
      bool _running;
      QSocketNotifier _notify;
      QTextStream _qtin;
  };
}
}

#endif
