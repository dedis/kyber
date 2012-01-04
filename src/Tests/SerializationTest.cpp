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

  TEST(Serialization, BitsRequired)
  {
    QBitArray bits(0, false);
    EXPECT_EQ(1, Serialization::BytesRequired(bits));
    
    QBitArray bits2(1, false);
    EXPECT_EQ(1, Serialization::BytesRequired(bits2));

    QBitArray bits3(10, false);
    EXPECT_EQ(2, Serialization::BytesRequired(bits3));

    QBitArray bits4(8, false);
    EXPECT_EQ(1, Serialization::BytesRequired(bits4));

    QBitArray bits5(16, false);
    EXPECT_EQ(2, Serialization::BytesRequired(bits5));
  }

  TEST(Serialization, WriteBitsEasy)
  {
    QByteArray msg(1, 'a');
    QBitArray bits(1, false);

    Serialization::WriteBitArray(bits, msg, 0);
    EXPECT_EQ((char)0x00, (char)msg[0]);

    QByteArray msg1(1, 'a');
    QBitArray bits1(0, false);

    Serialization::WriteBitArray(bits1, msg1, 0);
    EXPECT_EQ((char)0x00, (char)msg1[0]);

    QByteArray msg2(1, 'a');
    QBitArray bits2(1, true);

    Serialization::WriteBitArray(bits2, msg2, 0);
    EXPECT_EQ((char)0x01, (char)msg2[0]);

    QByteArray msg3(2, 'a');
    QBitArray bits3(8, true);

    Serialization::WriteBitArray(bits3, msg3, 0);
    EXPECT_EQ((char)0xFF, (char)msg3[0]);
    EXPECT_EQ((char)'a', (char)msg3[1]);

    QByteArray msg4(2, 'a');
    QBitArray bits4(8, true);

    Serialization::WriteBitArray(bits4, msg4, 1);
    EXPECT_EQ((char)'a', (char)msg4[0]);
    EXPECT_EQ((char)0xFF, (char)msg4[1]);

    QByteArray msg5(2, 'a');
    QBitArray bits5(9, true);

    Serialization::WriteBitArray(bits5, msg5, 0);
    EXPECT_EQ((char)0xFF, (char)msg5[0]);
    EXPECT_EQ((char)0x01, (char)msg5[1]);

    QByteArray msg6(2, 'a');
    QBitArray bits6(10, true);

    Serialization::WriteBitArray(bits6, msg6, 0);
    EXPECT_EQ((char)0xFF, (char)msg6[0]);
    EXPECT_EQ((char)0x03, (char)msg6[1]);
  }
  
  TEST(Serialization, WriteBitsHard)
  {
    QByteArray msg1(2, 'a');
    QBitArray bits1(12, true);

    Serialization::WriteBitArray(bits1, msg1, 0);
    EXPECT_EQ((char)0xFF, (char)msg1[0]);
    EXPECT_EQ((char)0x0F, (char)msg1[1]);

    bits1.setBit(0, false);
    Serialization::WriteBitArray(bits1, msg1, 0);
    EXPECT_EQ((char)0x7F, (char)msg1[0]);
    EXPECT_EQ((char)0x0F, (char)msg1[1]);

    bits1.setBit(11, false);
    Serialization::WriteBitArray(bits1, msg1, 0);
    EXPECT_EQ((char)0x7F, (char)msg1[0]);
    EXPECT_EQ((char)0x0E, (char)msg1[1]);

    QByteArray msg2(3, 'b');
    Serialization::WriteBitArray(bits1, msg2, 1);
    EXPECT_EQ((char)'b', (char)msg2[0]);
    EXPECT_EQ((char)0x7F, (char)msg2[1]);
    EXPECT_EQ((char)0x0E, (char)msg2[2]);
  }

  void ReadBitsHelper(int arrlen, int offset, int n_bits)
  {
    QByteArray msg(arrlen, 'a');
    QBitArray bits(n_bits, true);

    Serialization::WriteBitArray(bits, msg, offset);

    QBitArray out = Serialization::ReadBitArray(msg, offset, n_bits);
    EXPECT_EQ(n_bits, out.count());
    for(int i=0; i<n_bits; i++) {
      EXPECT_EQ(true, out[i]);
    }
  }

  TEST(Serialization, ReadBitsEasy) 
  {
    QByteArray msg(1, 'a');
    QBitArray bits(1, true);

    Serialization::WriteBitArray(bits, msg, 0);
    QBitArray out = Serialization::ReadBitArray(msg, 0, 1);
    ASSERT_EQ(1, out.count());
    ASSERT_EQ(true, out[0]);

    bits.setBit(0, false);

    Serialization::WriteBitArray(bits, msg, 0);
    QBitArray out2 = Serialization::ReadBitArray(msg, 0, 1);
    ASSERT_EQ(1, out2.count());

    ReadBitsHelper(2, 0, 8);
    ReadBitsHelper(2, 1, 8);
    ReadBitsHelper(2, 0, 9);
    ReadBitsHelper(3, 1, 9);
    ReadBitsHelper(3, 1, 10);
    ReadBitsHelper(3, 0, 20);
  }
  
  TEST(Serialization, ReadBitsHard) 
  {
    QByteArray msg(5, 'a');
    QBitArray bits(11, true);
    bits.setBit(0, false);
    bits.setBit(1, true);
    bits.setBit(2, false);
    bits.setBit(3, false);
    bits.setBit(4, true);
    bits.setBit(5, false);
    bits.setBit(6, false);
    bits.setBit(7, true);
    bits.setBit(8, true);
    bits.setBit(9, false);
    bits.setBit(10, false);

    Serialization::WriteBitArray(bits, msg, 0);
    QBitArray out = Serialization::ReadBitArray(msg, 0, 11);
    ASSERT_FALSE(out[0]);
    ASSERT_EQ(true, out[1]);
    ASSERT_FALSE(out[2]);
    ASSERT_FALSE(out[3]);
    ASSERT_EQ(true, out[4]);
    ASSERT_FALSE(out[5]);
    ASSERT_FALSE(out[6]);
    ASSERT_EQ(true, out[7]);
    ASSERT_EQ(true, out[8]);
    ASSERT_FALSE(out[9]);
    ASSERT_FALSE(out[10]);

    Serialization::WriteBitArray(bits, msg, 1);
    QBitArray out2 = Serialization::ReadBitArray(msg, 1, 11);
    ASSERT_FALSE(out2[0]);
    ASSERT_EQ(true, out2[1]);
    ASSERT_FALSE(out2[2]);
    ASSERT_FALSE(out2[3]);
    ASSERT_EQ(true, out2[4]);
    ASSERT_FALSE(out2[5]);
    ASSERT_FALSE(out2[6]);
    ASSERT_EQ(true, out2[7]);
    ASSERT_EQ(true, out2[8]);
    ASSERT_FALSE(out2[9]);
    ASSERT_FALSE(out2[10]);
  }
}
}
