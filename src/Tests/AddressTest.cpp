#include "DissentTest.hpp"

using Dissent::Transports::Address;
using Dissent::Transports::AddressFactory;
using Dissent::Transports::BufferAddress;

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
    const Address addr1 = AddressFactory::GetInstance().CreateAddress("buffer://9999");
    try {
      const Address tmp_addr = AddressFactory::GetInstance().CreateAddress("buffer://a");
      throw std::logic_error("Should not get here");
    } catch (Dissent::Transports::AddressException) { }
    const BufferAddress &baddr0 = static_cast<const BufferAddress &>(addr0);
    EXPECT_EQ(baddr0.GetId(), 1000);
    EXPECT_EQ(baddr0, addr0);
    EXPECT_NE(baddr0, addr1);

    const Address addr3 = AddressFactory::GetInstance().CreateAddress("buffer://1000");
    EXPECT_EQ(baddr0, addr3);

    const Address addr4 = AddressFactory::GetInstance().CreateAddress("test://a");
    const BufferAddress &baddr4 = static_cast<const BufferAddress &>(addr4);
    EXPECT_EQ(baddr4.GetId(), -1);
  }
}
}
