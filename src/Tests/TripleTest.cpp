#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {
  TEST(Triple, Basic)
  {
    typedef Triple<Id, QSharedPointer<AsymmetricKey>, QByteArray > my_triple;
    Library &lib = CryptoFactory::GetInstance().GetLibrary();

    Id id0;
    QSharedPointer<AsymmetricKey> key0(lib.CreatePrivateKey());
    QSharedPointer<AsymmetricKey> pkey0(key0->GetPublicKey());
    QSharedPointer<DiffieHellman> dh0(lib.CreateDiffieHellman());
    QByteArray pub0 = dh0->GetPublicComponent();

    Id id1;
    QSharedPointer<AsymmetricKey> key1(lib.CreatePrivateKey());
    QSharedPointer<AsymmetricKey> pkey1(key1->GetPublicKey());
    QSharedPointer<DiffieHellman> dh1(lib.CreateDiffieHellman());
    QByteArray pub1 = dh1->GetPublicComponent();

    my_triple t0(id0, pkey0, pub0);
    my_triple t0_0(id0, pkey0, pub0);
    my_triple t1(id1, pkey1, pub1);

    EXPECT_EQ(t0, t0_0);
    EXPECT_NE(t0, t1);

    QByteArray data;
    QDataStream istream(&data, QIODevice::WriteOnly);
    istream << t1;

    QDataStream ostream(data);
    my_triple t1_0;
    EXPECT_NE(t1, t1_0);

    ostream >> t1_0;
    EXPECT_EQ(t1, t1_0);
    EXPECT_EQ(t1.first, t1_0.first);
    EXPECT_EQ(*t1.second, *t1_0.second);
    EXPECT_NE(t1.second, t1_0.second);
    EXPECT_EQ(t1.third, t1_0.third);
  }
}
}
