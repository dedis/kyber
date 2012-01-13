#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {
  TEST(Address, Basic) {
    const Address addr = AddressFactory::GetInstance().CreateAddress("udp://localhost:11432");
    QUrl url = QUrl("udp://localhost:11432");
    const Address addr0 = AddressFactory::GetInstance().CreateAddress(url.toString());
    EXPECT_EQ(addr.GetUrl(), url);
    EXPECT_EQ(url, addr0.GetUrl());
    EXPECT_EQ(addr.GetUrl().port(), 11432);
    EXPECT_EQ(addr.GetUrl().scheme(), "udp");
    EXPECT_EQ(addr.GetUrl().host(), "localhost");
    EXPECT_EQ(addr, addr0);
  }

  TEST(Address, Buffer) {
    const Address addr0 = AddressFactory::GetInstance().CreateAddress("buffer://1000");
    EXPECT_TRUE(addr0.Valid());

    const Address addr1 = AddressFactory::GetInstance().CreateAddress("buffer://9999");
    EXPECT_TRUE(addr1.Valid());

    const Address bad_addr = AddressFactory::GetInstance().CreateAddress("buffer://a");
    EXPECT_FALSE(bad_addr.Valid());

    const BufferAddress &baddr0 = static_cast<const BufferAddress &>(addr0);
    EXPECT_EQ(baddr0.GetId(), 1000);
    EXPECT_EQ(baddr0, addr0);
    EXPECT_NE(baddr0, addr1);

    const Address addr3 = AddressFactory::GetInstance().CreateAddress("buffer://1000");
    EXPECT_EQ(baddr0, addr3);

    const Address addr4 = AddressFactory::GetInstance().CreateAddress("test://a");
    const BufferAddress &baddr4 = static_cast<const BufferAddress &>(addr4);
    EXPECT_EQ(baddr4.GetId(), -1);
    EXPECT_FALSE(addr4.Valid());
    EXPECT_FALSE(baddr4.Valid());
  }

  TEST(Address, Tcp) {
    const Address addr0 = AddressFactory::GetInstance().CreateAddress("tcp://:1000");
    const Address addr1 = AddressFactory::GetInstance().CreateAddress("tcp://:9999");
    const Address any = TcpAddress();
    const TcpAddress &taddr0 = static_cast<const TcpAddress &>(addr0);
    EXPECT_EQ(taddr0.GetPort(), 1000);
    EXPECT_EQ(taddr0, addr0);
    EXPECT_NE(taddr0, addr1);

    Address addr3 = AddressFactory::GetInstance().CreateAddress("tcp://:1000");
    EXPECT_EQ(taddr0, addr3);

    addr3 = AddressFactory::GetInstance().CreateAddress("tcp://abcd:1000");
    EXPECT_NE(taddr0, addr3);
    addr3 = TcpAddress("asdfasdf", -1);
    EXPECT_FALSE(addr3.Valid());
    addr3 = TcpAddress("asdf://asdfasdf:654452345");
    EXPECT_FALSE(addr3.Valid());
    addr3 = TcpAddress("http://asdfasdf:2345");
    EXPECT_FALSE(addr3.Valid());
  }

  TEST(Address, Relay) {
    RelayAddress::AddressFactoryEnable();
    Id id0;
    Id id1;
    const Address addr0 = AddressFactory::GetInstance().CreateAddress("relay:///" + id0.ToString());
    const Address addr1 = AddressFactory::GetInstance().CreateAddress("relay:///" + id1.ToString());
    const Address any = RelayAddress();
    const RelayAddress &raddr0 = static_cast<const RelayAddress &>(addr0);
    EXPECT_EQ(raddr0.GetId(), id0);
    EXPECT_EQ(raddr0.GetId().ToString(), id0.ToString());
    EXPECT_EQ(raddr0, addr0);
    EXPECT_NE(raddr0, addr1);

    Address addr3 = AddressFactory::GetInstance().CreateAddress("relay:///" + id0.ToString());
    EXPECT_EQ(raddr0, addr3);

    addr3 = AddressFactory::GetInstance().CreateAddress("relay:///#####");
    EXPECT_NE(raddr0, addr3);
    EXPECT_FALSE(addr3.Valid());
    addr3 = RelayAddress(Id(QString("$$$$")));
    EXPECT_FALSE(addr3.Valid());
  }
}
}
