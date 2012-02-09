#include "Bootstrapper.hpp"
#include "Connection.hpp"

using Dissent::Utils::Timer;
using Dissent::Utils::TimerCallback;
using Dissent::Utils::TimerMethod;

namespace Dissent {
namespace Connections {
  Bootstrapper::Bootstrapper(ConnectionManager &cm,
      const QList<Address> &remote_endpoints) :
    ConnectionAcquirer(cm),
    _remote_endpoints(remote_endpoints),
    _bootstrap_event(0)
  {
  }

  Bootstrapper::~Bootstrapper()
  {
    if(_bootstrap_event) {
      _bootstrap_event->Stop();
      delete _bootstrap_event;
    }
  }

  void Bootstrapper::OnStart()
  {
    Bootstrap(0);
  }

  void Bootstrapper::OnStop()
  {
    if(_bootstrap_event) {
      _bootstrap_event->Stop();
      delete _bootstrap_event;
      _bootstrap_event = 0;
    }
  }

  void Bootstrapper::HandleConnection(Connection *con)
  {
    const Address &addr = con->GetEdge()->GetRemotePersistentAddress();
    if(!_remote_endpoints.contains(addr)) {
      _remote_endpoints.append(addr);
    }

    QObject::connect(con, SIGNAL(Disconnected(const QString &)),
        this, SLOT(HandleDisconnect(const QString &)));
  }

  void Bootstrapper::HandleConnectionAttemptFailure(const Address &,
          const QString &)
  {
    Bootstrap(0);
  }

  void Bootstrapper::Bootstrap(const int &val)
  {
    if(!NeedConnection() || Stopped()) {
      if(_bootstrap_event) {
        _bootstrap_event->Stop();
        delete _bootstrap_event;
        _bootstrap_event = 0;
      }
      return;
    } else if(_bootstrap_event == 0) {
      TimerCallback *cb = new TimerMethod<Bootstrapper, int>(this, &Bootstrapper::Bootstrap, -1);
      _bootstrap_event = new TimerEvent(Timer::GetInstance().QueueCallback(cb, 5000, 5000));
    } else if(val != -1) {
      return;
    }

    foreach(const Address &addr, _remote_endpoints) {
      GetConnectionManager().ConnectTo(addr);
    }
  }

  void Bootstrapper::HandleDisconnect(const QString &)
  {
    Bootstrap(0);
  }

  bool Bootstrapper::NeedConnection()
  {
    return GetConnectionManager().GetConnectionTable().GetConnections().count() == 1;
  }
}
}
