#include "Utils/Utils.hpp"
#include "RsaPrivateKey.hpp"

namespace Dissent {
namespace Crypto {
  int RsaPrivateKey::DefaultKeySize()
  {
    if(Utils::Testing) {
      return 512;
    } else {
      return 2048;
    }
  }
}
}
