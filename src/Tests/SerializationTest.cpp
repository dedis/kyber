#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {
  TEST(Serialization, Integers)
  {
    QByteArray msg(10, 'a');

    Serialization::WriteInt(2, msg, 2);
    EXPECT_EQ(2, Serialization::ReadInt(msg, 2));
    Serialization::WriteInt(-1, msg, 5);
    EXPECT_EQ(-1, Serialization::ReadInt(msg, 5));
    Serialization::WriteUInt(4294967200u, msg, 1);
    EXPECT_EQ(4294967200u, (uint) Serialization::ReadInt(msg, 1));
  }
}
}
