#include "EdgeFactory.hpp"

namespace Dissent {
namespace Transports {
  void EdgeFactory::AddEdgeListener(QSharedPointer<EdgeListener> el)
  {
    if(_type_to_el.contains(el->GetAddressType())) {
      qFatal(QString("Attempting to create multiple EdgeListeners with the " 
        "same address type: " + el->GetAddressType()).toUtf8().data());
    }
    _type_to_el[el->GetAddressType()] = el;
  }

  void EdgeFactory::CreateEdgeTo(const Address &to)
  {
    if(_type_to_el.contains(to.GetType())) {
      _type_to_el[to.GetType()]->CreateEdgeTo(to);
    } else {
      qWarning() << "No EdgeListener registered for type:" << to.GetType();
    }
  }

  void EdgeFactory::Stop()
  {
    foreach(const QSharedPointer<EdgeListener> &el, _type_to_el) {
      el->Stop();
    }
  }
}
}
