#ifndef DISSENT_CRYPTO_ABSTRACT_GROUP_EC_PARAMS_H_GUARD
#define DISSENT_CRYPTO_ABSTRACT_GROUP_EC_PARAMS_H_GUARD

#include "Crypto/Integer.hpp"

namespace Dissent {
namespace Crypto {
namespace AbstractGroup {

  /**
   * All curves here have the form 
   *  y^2 = x^3 + ax + b  (mod p)
   */
  class ECParams {

    public:

      typedef enum {
        NIST_P192 = 0,
        NIST_P224,
        NIST_P256,
        NIST_P384,
        NIST_P521,
        INVALID
      } CurveName;

      ECParams(CurveName n);

      ~ECParams() {};

      inline bool IsNistCurve() const { return _is_nist_curve; }

      inline Integer GetP() const { return _p; }
      inline Integer GetQ() const { return _q; }
      inline Integer GetA() const { return _a; }
      inline Integer GetB() const { return _b; }
      inline Integer GetGx() const { return _gx; }
      inline Integer GetGy() const { return _gy; }


    private:

      bool _is_nist_curve;

      Integer _p; // field size
      Integer _q; // group order

      Integer _a;
      Integer _b;

      Integer _gx;
      Integer _gy;
  };

}
}
}

#endif
