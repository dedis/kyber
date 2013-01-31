
#include "ECParams.hpp"

namespace Dissent {
namespace Crypto {
namespace AbstractGroup {

  ECParams::ECParams(CurveName n) :
    _is_nist_curve(true),
    _a(-3L)
  {
    // All NIST curves have a = -3

    const char *p192_p = "0xfffffffffffffffffffffffffffffffeffffffffffffffff";
    const char *p192_q = "0xffffffffffffffffffffffff99def836146bc9b1b4d22831";
    const char *p192_b = "0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1";
    const char *p192_gx = "0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012";
    const char *p192_gy = "0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811";

    const char *p224_p = "0xffffffffffffffffffffffffffffffff000000000000000000000001";
    const char *p224_q = "0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d";
    const char *p224_b = "0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4";
    const char *p224_gx = "0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21";
    const char *p224_gy = "0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34";

    const char * p256_p = "0xFFFFFFFF000000010000000000"
        "00000000000000FFFFFFFFFFFFFFFFFFFFFFFF";
    const char * p256_q = "0xFFFFFFFF00000000FFFFFFFFFF"
        "FFFFFFBCE6FAADA7179E84F3B9CAC2FC632551";
    const char * p256_b = "0x5AC635D8AA3A93E7B3EBBD5576"
        "9886BC651D06B0CC53B0F63BCE3C3E27D2604B";
    const char * p256_gx = "0x6B17D1F2E12C4247F8BCE6E56"
         "3A440F277037D812DEB33A0F4A13945D898C296";
    const char * p256_gy = "0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE3"
         "3576B315ECECBB6406837BF51F5";

    const char * p384_p = "0xffffffffffffffffffffffffffffffffffffffff"
        "fffffffffffffffffffffffeffffffff0000000000000000ffffffff";
    const char * p384_q = "0xffffffffffffffffffffffffffffffffffffffffffffffff"
        "c7634d81f4372ddf581a0db248b0a77aecec196accc52973";
    const char * p384_b = "0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe814112"
        "0314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef ";
    const char * p384_gx = "0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b98"
         "59f741e082542a385502f25dbf55296c3a545e3872760aB7";
    const char * p384_gy = "0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147c"
         "e9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5F";

    const char * p521_p = "0x000001ffffffffffffffffffffffffffffffffffffffffff"
        "ffffffffffffffffffffffffffffffffffffffffffffffff"
        "ffffffffffffffffffffffffffffffffffffffff";
    const char * p521_q = "0x000001ffffffffffffffffffffffffffffffffffffffffff"
        "fffffffffffffffffffffffa51868783bf2f966b7fcc0148"
        "f709a5d03bb5c9b8899c47aebb6fb71e91386409";
    const char * p521_b = "0x00000051953eb9618e1c9a1f929a21a0b68540eea2da725b"
        "99b315f3b8b489918ef109e156193951ec7e937b1652c0bd"
        "3bb1bf073573df883d2c34f1ef451fd46b503f00";
    const char * p521_gx = "0x000000c6858e06b70404e9cd9e3ecb662395b4429c648139"
          "053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127"
          "a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66";
    const char * p521_gy = "0x0000011839296a789a3bc0045c8a5fb42c7d1bd998f54449"
          "579b446817afbd17273e662c97ee72995ef42640c550b901"
          "3fad0761353c7086a272c24088be94769fd16650";

    switch(n) {
      case NIST_P192:
        _p = Integer(QByteArray::fromHex(p192_p));
        _q = Integer(QByteArray::fromHex(p192_q));
        _b = Integer(QByteArray::fromHex(p192_b));
        _gx = Integer(QByteArray::fromHex(p192_gx));
        _gy = Integer(QByteArray::fromHex(p192_gy));
        break;

      case NIST_P224:
        _p = Integer(QByteArray::fromHex(p224_p));
        _q = Integer(QByteArray::fromHex(p224_q));
        _b = Integer(QByteArray::fromHex(p224_b));
        _gx = Integer(QByteArray::fromHex(p224_gx));
        _gy = Integer(QByteArray::fromHex(p224_gy));
        break;

      case NIST_P256:
        _p = Integer(QByteArray::fromHex(p256_p));
        _q = Integer(QByteArray::fromHex(p256_q));
        _b = Integer(QByteArray::fromHex(p256_b));
        _gx = Integer(QByteArray::fromHex(p256_gx));
        _gy = Integer(QByteArray::fromHex(p256_gy));
        break;

      case NIST_P384:
        _p = Integer(QByteArray::fromHex(p384_p));
        _q = Integer(QByteArray::fromHex(p384_q));
        _b = Integer(QByteArray::fromHex(p384_b));
        _gx = Integer(QByteArray::fromHex(p384_gx));
        _gy = Integer(QByteArray::fromHex(p384_gy));
        break;

      case NIST_P521:
        _p = Integer(QByteArray::fromHex(p521_p));
        _q = Integer(QByteArray::fromHex(p521_q));
        _b = Integer(QByteArray::fromHex(p521_b));
        _gx = Integer(QByteArray::fromHex(p521_gx));
        _gy = Integer(QByteArray::fromHex(p521_gy));
        break;

      default:
        qFatal("Unknown curve");

      Q_ASSERT(_p > 0);
    }
  }

}
}
}

