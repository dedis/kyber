
#include "IntegerElementData.hpp"
#include "IntegerGroup.hpp"

namespace Dissent {
namespace Crypto {
namespace AbstractGroup {

  IntegerGroup::IntegerGroup(const Integer &p, const Integer &g) :
      _p(p), 
      _g(g),
      _q((p-1)/2)
    {};

  IntegerGroup::IntegerGroup(const char *p_bytes, const char *g_bytes) :
    _p(QByteArray::fromHex(p_bytes)),
    _g(QByteArray::fromHex(g_bytes)),
    _q((_p-1)/2)
  {
    Q_ASSERT(_p>0);
    Q_ASSERT(_q>0);
    Q_ASSERT(_g>0);

    if(_g.Pow(2, _p) == 1)
      qFatal("g does not generate G*_p");
  }

  QSharedPointer<AbstractGroup> IntegerGroup::Copy() const
  {
    return QSharedPointer<IntegerGroup>(new IntegerGroup(*this));
  }

  QSharedPointer<IntegerGroup> IntegerGroup::GetGroup(GroupSize size) 
  {
    const char *bytes_p;
    const char *bytes_g;

    switch(size) {
      case TESTING_256:
        bytes_p = "0xd0a5cae1cd4b9ebbd66c5172d9cd33ec61ca04e3abd2d5afb"
                              "43f0a5ddd18d57b";
        bytes_g = "0x03";
        break;

      case TESTING_512:
        bytes_p = "0xdc5c01de17673c056ca799ed5855b16f3c3b76b65fe266313faa628fc8d845cf2"
                  "421757e69fb9c7b2e9070b297cc8c6a5fa923e334ea0ba862a0e73c77ca8e03";
        bytes_g = "0x03";
        break;

      case TESTING_768:
        bytes_p = "0xd0960a13d4bc55f540705e34cd1eced6d00d439c09407f41b60df1f431d2b63ac"
                  "5aec343c2aa9a3e0c317a109f815cae66673cd5a5a109fc394c06f8a50809543"
                  "799d3c2543b1eb1e2c3ddfd04018136e166eb8013e491250889135bafcf5b5f";
        bytes_g = "0x02";
        break;

      case PRODUCTION_1024:
        bytes_p = "0xfd8a16fc2afdaeb2ea62b66b355f73e6c2fc4349bf4551793"
                              "36ca1b45f75d68da0101cba63c22efd5f72e5c81dc30cf709da"
                              "aef2323e950160926e11ef8cbf40a26496668749218b5620276"
                              "697c2d1536b31042ad846e1e5758d79b3e4e0b5bc4c5d3a4e95"
                              "da4502e9058ea3beade156d8234e35d5164783c57e6135139db"
                              "097";
        bytes_g = "0x02";
        break;

      case PRODUCTION_1536:
        bytes_p = "0x9de8381ca41a380e266a2b59578dddc790a3c54943b9ed2c5082fc5437f3ff8c7"
                    "43ea65f00dd7c755410b18e65a67701c8f627b781e9a72d069979852d172bdf9"
                    "f1ebdb812a100984316cd53b37e9c79e07765c4f9009280a13fbe3f4f882a9ba"
                    "4cb7f2bf95ef783185baa37b91860eeb1bf3d59302d00be0a5e8d26089902d8d"
                    "05a31b680e0775e310243089bebcd13108f24ca4ced30820ddf2e2f539199e42"
                    "809c94b6c62277cf182cf7b9cfe8f78a075e31765b732fc49f751c55a78de93";
        bytes_g = "0x03";
        break;

      case PRODUCTION_2048:
        bytes_p = "0xfddb8c605ec022e00980a93695b6e16f776f8db658c40163d"
                              "2cfb2f57d0d685076311697065cf78657fa6819000e9ea923c1"
                              "b488cd734f7c8585e97f7515bad667ecba98c4c271db8126703"
                              "a4d4e62238aad384d69f5ccb77fa0fb2569879ca672be6a9228"
                              "0ada08627be1b96371964b35f0e8ac655014a9293ac9dcf1e26"
                              "c9a43a4027ee504d06d60d3819dabaec3268b950932376d146a"
                              "75debb715b366e6fbc3efbb31960382798496dab78f03460b99"
                              "cf204153084ea8e6a6a32fcefa8106f0a1e24246681ba0e2e47"
                              "365d7e84016fd3e2f3ed72022a61c981c3194206d727fceab01"
                              "781cdcc0d3b2c680aa7573471fe781c2e081354cbcf7e94a6a1"
                              "c9df";
        bytes_g = "0x02";

      case PRODUCTION_2560:
        bytes_p = "0x80ffc8a1d0073b68225872eedfd10cc2e1bde3246c0f5132b1a34518d791d10a4"
                    "315f7b4bc8935629a3b20a9b992754319ac8ddbabeb9971b991cc2fd9f9ba2ae"
                    "b5061f232917efae2fd24b71564525787f0e6ee39a3bd4b5c271a4a636d6a282"
                    "d583263dfccb0d2b86bde652901a88995cb4ed313d0acc85ab9be735a9cee867"
                    "8668ac08280e029ff5e1e67d703850addf96083dbf5b3c1d22a5fa035422f1e7"
                    "9355f9d27b949f498470eaa28762389379e1c6c1574b7d5beb55ad5611f00072"
                    "9470ad08d7258593fd007f410814e3d1fb0e3e7e839023f16ebdc67ef22807c6"
                    "6be43b184f9392f7b6b8ade221fb1b1862094943d04437205cebb851d8bdbd8d"
                    "d7b47e8ccf5a1a2f56ab99ed3c586c51c2ba5a5e7ffeb51b5a01ea6bba3f9caf"
                    "cfeecdec6a258e41d2537b4cbeae761d1d85817d3cfa27f00c2166ea3fc08eb";
        bytes_g = "0x03";
        break;

      case PRODUCTION_3072:
        bytes_p = "0xcdace3ce7ae743afaff76655112ec359e181758de4a5cbbf5b6e64104e52be8a4"
                  "9a8f62332790da1e5fba7a8dbcfe5687ac62d8ed5d36e4650557304c8d0808b8"
                  "51bf82cc9c9b2d8772326836d4a146d1e44b7509748c0568014ec12294763539"
                  "f1df204babffb0f2a402b5a200e950568156183f051046bcdc3d6e8f35409917"
                  "4b35b3faec71c07e0f423a9514e11f6a6fe5694078a8aef48ef33814e0c32dc3"
                  "f983f7322c35f10d17c0a82609665cda0743eae55a586a9080dc7116cee01474"
                  "94dfe3d57f38c4a799a8216111254c6a3c3bb5f99ada3509106b263bd6b2d262"
                  "bc0f06e9063763d26aacfc6737f710bc2eba6cbf0917494f0c8065425f217ed8"
                  "2053b54c1df813d59134e89108d32f9902b9cb1711b674f9706bfd89f8252d40"
                  "67af469bd19827579a81cd5b48ef4bc83682f0857d1a9259d9fe59a20eaabfd9"
                  "74849a7bdf94120ddc748a0ec7babba10c2a1a8a4ee2055e32cdfade9eb3a224"
                  "09fe872a62bcff12c65de2fb996b3d992e6ffe3d7bf0ec45588d8375227d603";
        bytes_g = "0x03";
        break;

      case PRODUCTION_3584:
        bytes_p = "0xf8f085a3e02ec166b8cbed27ed20db3d05efc06d84c99b6f844c0f2f95bf2f460"
                    "6281d62bbc7328eac73921cd926b5ce7e5d15a2c9abb7e2be70e2644c91955fc"
                    "772c7876ed4e7fd6def5a9a28d22951ee8a20119d02b539923d5292b8323e0c0"
                    "0ff7546e7e92e457076e7b07a3cc0d4b24eeea19cd3d089b3f29a74e0ed11d9f"
                    "4201e7b3bb316c79feb596f6756461b33e6eee09b4f36165300ab53f0f62c375"
                    "80fe31ad4edd83ae166b22fb62b872f3895f75c0ea9f8a8e117f6c1db0fe8ade"
                    "5c89654ca1faf59e949872a2941898cb3a4eae8406296a42036fd204651084a5"
                    "45e8ebcce7e305be262d0f271f5af3c1db32da5e1867d0b68497bb436b57e67d"
                    "c9596d451f06e9a11a494958cd34dfccd722c7e877162dfd13d9ab6127925023"
                    "fa06610c1c404b7fbdf0cfa3b2727c999682793bc883ce587a67901dcbf49333"
                    "661fc139f41db69c64e42b98d120fdb7f0c858395e6fdf27738e9f48351dc9c4"
                    "2d0689ea9f14c1683928784b65a899f137c2e306cecaedac4b30509e39026fac"
                    "742fb2343d99bb1dac16936de692981e7e393aeb84d5f84dc07c314f9d161219"
                    "a98de3a78fbc4dd74a2c6b24d177f76fce1a59d6cdb79a3024d228ff6407f5b";
        bytes_g = "0x03";
        break;

      case PRODUCTION_4096:
        bytes_p = "0xd21cbedd532438bb0c4c0e2654ddb90f93e76e366611259524ed0db279dff81ce"
                    "0078086d60425e7a30f011f04003040898b7c2adafe74670c399402cfe846126"
                    "dacab0e21809ee41bfc3aa939d9de90d3ac4b55c87fd09f5a21ddd3e78d15575"
                    "a775414cce6bf1de3512189bfebddb2b871fa7824061d43db64a6468aaf936b3"
                    "7a9dd78f7ef57a3d01e77f069ee76d2ceae4da60a153b390a5aa986d6a8fe3c0"
                    "73c565182d72a2df385d35ef9a6e3e39cb7cb9af22e67e05e0b004aab7570821"
                    "61c3119a6e5539b0fbc9b344d32b27dc04eef6b755103bc57c1f962dc6c555f4"
                    "16c4678c71829d69ce77f8ba2a94be7eed828bcc14b24d185bd2c1ab6d8d7826"
                    "9dce13e394a6a0c3afebfbe79b807c24a3a7a22fb3974a18f70c5394f0590003"
                    "e1144ed1efb1257f416cb4e423fc5434619c3026704e3743696c22bd8d01fc9c"
                    "6884ab62dbcb48e7e57122d305a2e0ca9a4f2bf1cbf241414b4398863d30e4b3"
                    "a0da32e56fe443768d3c4c790e9476d566ab9390641576a2d23c70aa781da90d"
                    "6a2203cac8fec411d531a59226fd1e1ae49bce900345226967d22046f540685a"
                    "a920a7dba6d45e4fbb5dcc6a5406c64c46dd860f5902ee0a920e96b71ecf36b1"
                    "ac8798b6db32077c8ac7a2bd1dff627d614deeea5a4f9ca912e6666d646308bc"
                    "d55376e7def94783527283cfac94f26ad3116b1513d65fa3bb5307d71d6f9bf";
        bytes_g = "0x02";
        break;

      default:
        qFatal("Illegal group type");
    }

    return QSharedPointer<IntegerGroup>(new IntegerGroup(bytes_p, bytes_g));
  }

  QSharedPointer<IntegerGroup> IntegerGroup::Zero() 
  {
    return QSharedPointer<IntegerGroup>(new IntegerGroup(Integer(0), Integer(0))); 
  }


  Element IntegerGroup::Multiply(const Element &a, const Element &b) const
  {
    return Element(new IntegerElementData((GetInteger(a).MultiplyMod(GetInteger(b), _p)))); 
  }

  Element IntegerGroup::Exponentiate(const Element &a, const Integer &exp) const
  {
    return Element(new IntegerElementData(GetInteger(a).Pow(exp, _p))); 
  }
  
  Element IntegerGroup::CascadeExponentiate(const Element &a1, const Integer &e1,
      const Element &a2, const Integer &e2) const
  {
    return Element(new IntegerElementData(
          _p.PowCascade(GetInteger(a1), e1, GetInteger(a2), e2)));
  }

  Element IntegerGroup::Inverse(const Element &a) const
  {
    return Element(new IntegerElementData(GetInteger(a).ModInverse(_p)));
  }
  
  QByteArray IntegerGroup::ElementToByteArray(const Element &a) const
  {
    return GetInteger(a).GetByteArray();
  }
  
  Element IntegerGroup::ElementFromByteArray(const QByteArray &bytes) const 
  {
    return Element(new IntegerElementData(Integer(bytes)));
  }

  bool IntegerGroup::IsElement(const Element &a) const 
  {
    return (GetInteger(a).Pow(_q, _p) == 1);
  }

  bool IntegerGroup::IsIdentity(const Element &a) const 
  {
    return (GetInteger(a) == 1);
  }

  Integer IntegerGroup::RandomExponent() const
  {
    return Integer::GetRandomInteger(1, _q, false); 
  }

  Element IntegerGroup::RandomElement() const
  {
    return Element(new IntegerElementData(_g.Pow(RandomExponent(), _p)));
  }

  Integer IntegerGroup::GetInteger(const Element &e) const
  {
    return IntegerElementData::GetInteger(e.GetData());
  }

  Element IntegerGroup::EncodeBytes(const QByteArray &in) const
  {
    // We can store p bytes minus 2 bytes for padding and one more to be safe
    const int can_read = BytesPerElement();

    if(can_read < 1) qFatal("Illegal parameters");
    if(in.count() > can_read) qFatal("Cannot encode: string is too long");

    // Add initial 0xff byte and trailing 0x00 byte
    QByteArray padded;
    padded.append(0xff);
    padded.append(in.left(can_read));
    padded.append((char)0x00);
    padded.append(0xff);

    // Change byte of padded string until the
    // integer represented by the byte arry is a quadratic
    // residue. We need to be sure that every plaintext
    // message is a quadratic residue modulo p
    const int last = padded.count()-2;

    for(unsigned char pad=0x00; pad < 0xff; pad++) {
      padded[last] = pad;

      Element element(new IntegerElementData(Integer(padded)));
      if(IsElement(element)) {
        return element;
      }
    }

    qFatal("Could not encode message as quadratic residue");
    return Element(new IntegerElementData(Integer(1)));
  }
 
  bool IntegerGroup::DecodeBytes(const Element &a, QByteArray &out) const
  {
    QByteArray data = ElementToByteArray(a);
    if(data.count() < 3) {
      qWarning() << "Tried to decode invalid plaintext (too short):" << data.toHex();
      return false;
    }

    const unsigned char cfirst = data[0];
    const unsigned char clast = data.right(1)[0];
    if(cfirst != 0xff || clast != 0xff) {
      qWarning() << "Tried to decode invalid plaintext (bad padding)";
      return false;
    }

    out = data.mid(1, data.count()-3);
    return true;
  }

  bool IntegerGroup::IsProbablyValid() const
  {
    // g != -1, 0, 1
    if(_g == 0 || _g == 1 || _g == Integer(-1).Modulo(_p))
      return false;

    // g^q = 1
    if(_g.Pow(_q, _p) != 1)
      return false;

    return true;
  }

  QByteArray IntegerGroup::GetByteArray() const
  {
    QByteArray out;
    QDataStream stream(&out, QIODevice::WriteOnly);

    stream << _p << _g << _q;

    return out;
  }

  bool IntegerGroup::IsGenerator(const Element &a) const 
  {
    return IsElement(a) 
      && ((Exponentiate(a, GetOrder()) == GetIdentity()))
      && (!(Exponentiate(a, Integer(2)) == GetIdentity()));
  }


}
}
}
