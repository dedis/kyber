#include "EdgeListenerFactory.hpp"
#include "BufferEdgeListener.hpp"

namespace Dissent {
namespace Transports {
  EdgeListenerFactory &EdgeListenerFactory::GetInstance()
  {
    static EdgeListenerFactory elf;
    return elf;
  }

  EdgeListenerFactory::EdgeListenerFactory()
  {
    AddCallback("buffer", BufferEdgeListener::Create);
  }

  void EdgeListenerFactory::AddCallback(const QString &type, Callback cb)
  {
    _type_to_callback[type] = cb;
  }

  EdgeListener *EdgeListenerFactory::CreateEdgeListener(const Address &addr)
  {
    Callback cb = _type_to_callback[addr.GetType()];
    if(cb == 0) {
      qCritical() << "No such type registered:" << addr.GetType();
      return 0;
    }
    return cb(addr);
  }
}
}
