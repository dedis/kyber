#include "EdgeFactory.hpp"

namespace Dissent {
namespace Transports {
  void EdgeFactory::AddEdgeListener(QSharedPointer<EdgeListener> el)
  {
    if(_type_to_el.contains(el->GetAddressType())) {
      qFatal("%s", QString("Attempting to create multiple EdgeListeners with the " 
        "same address type: " + el->GetAddressType()).toUtf8().data());
    }
    _type_to_el[el->GetAddressType()] = el;
  }

  bool EdgeFactory::CreateEdgeTo(const Address &to)
  {
    if(_type_to_el.contains(to.GetType())) {
      _type_to_el[to.GetType()]->CreateEdgeTo(to);
      return true;
    } 
    qWarning() << "No EdgeListener registered for type:" << to.GetType();
    return false;
  }

  QSharedPointer<EdgeListener> EdgeFactory::GetEdgeListener(QString type)
  {
    return _type_to_el.value(type);
  }

  void EdgeFactory::Stop()
  {
    foreach(const QSharedPointer<EdgeListener> &el, _type_to_el) {
      el->Stop();
    }
  }
}
}
