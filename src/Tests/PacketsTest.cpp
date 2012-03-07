#include "DissentTest.hpp"

#include <QByteArray>
#include <QHostAddress>
#include <QSharedPointer>

namespace Dissent {
namespace Tests {

  TEST(Packets, FinishPacket)
  {
    QByteArray conn0("conn0conn0conn0conn0");

    FinishPacket finp0(conn0);

    EXPECT_EQ(Packet::PacketType_Finish, finp0.GetType());
    EXPECT_EQ(conn0, finp0.GetConnectionId());
    EXPECT_EQ(0, finp0.GetPayloadLength());

    QByteArray ser_finp0 = finp0.ToByteArray();

    int bytes_read = 0;
    QSharedPointer<Packet> pp0(Packet::ReadPacket(ser_finp0, bytes_read));

    ASSERT_FALSE(pp0.isNull());
    ASSERT_EQ(ser_finp0.count(), bytes_read);
    EXPECT_EQ(Packet::PacketType_Finish, pp0->GetType());
    EXPECT_EQ(conn0, pp0->GetConnectionId());
    EXPECT_EQ(0, pp0->GetPayloadLength());
  }

  TEST(Packets, TcpRequestPacket)
  {
    QByteArray conn0("conn0conn0conn0conn0");
    QByteArray sig0("sigsig");
    QByteArray req_data0("reqreqreqreq0000");

    const int payload_len = 4 + sig0.count() + req_data0.count();

    TcpRequestPacket req0(conn0, sig0, req_data0);

    EXPECT_EQ(Packet::PacketType_TcpRequest, req0.GetType());
    EXPECT_EQ(conn0, req0.GetConnectionId());
    EXPECT_EQ(payload_len, req0.GetPayloadLength());
    EXPECT_EQ(sig0, req0.GetSignature());
    EXPECT_EQ(req_data0, req0.GetRequestData());

    QByteArray ser_req0 = req0.ToByteArray();

    int bytes_read = 0;
    QSharedPointer<Packet> pp0(Packet::ReadPacket(ser_req0, bytes_read));

    ASSERT_FALSE(pp0.isNull());
    ASSERT_EQ(ser_req0.count(), bytes_read);
    EXPECT_EQ(Packet::PacketType_TcpRequest, pp0->GetType());
    EXPECT_EQ(conn0, pp0->GetConnectionId());
    EXPECT_EQ(payload_len, pp0->GetPayloadLength());

    TcpRequestPacket* rp = dynamic_cast<TcpRequestPacket*>(pp0.data());
    ASSERT_TRUE(rp);
    EXPECT_EQ(sig0, rp->GetSignature());
    EXPECT_EQ(req_data0, rp->GetRequestData());
  }

  TEST(Packets, TcpResponsePacket)
  {
    QByteArray conn0("conn0conn0conn0conn0");
    QByteArray resp_data0("resprespsfasdfasdfwjlhfw213984723948");

    const int payload_len = resp_data0.count();

    TcpResponsePacket resp0(conn0, resp_data0);

    EXPECT_EQ(Packet::PacketType_TcpResponse, resp0.GetType());
    EXPECT_EQ(conn0, resp0.GetConnectionId());
    EXPECT_EQ(payload_len, resp0.GetPayloadLength());
    EXPECT_EQ(resp_data0, resp0.GetResponseData());

    QByteArray ser_resp0 = resp0.ToByteArray();

    int bytes_read = 0;
    QSharedPointer<Packet> pp0(Packet::ReadPacket(ser_resp0, bytes_read));

    ASSERT_FALSE(pp0.isNull());
    ASSERT_EQ(ser_resp0.count(), bytes_read);
    EXPECT_EQ(Packet::PacketType_TcpResponse, pp0->GetType());
    EXPECT_EQ(conn0, pp0->GetConnectionId());
    EXPECT_EQ(payload_len, pp0->GetPayloadLength());

    TcpResponsePacket* rp = dynamic_cast<TcpResponsePacket*>(pp0.data());
    ASSERT_TRUE(rp);
    EXPECT_EQ(resp_data0, rp->GetResponseData());
  }

  /*
  TEST(Packets, TcpStartPacketAddress)
  {
    QByteArray verif_key("verifverifverifverif");
    QHostAddress addr("192.168.123.123");
    quint16 port = 12345;

    TcpStartPacket start0(verif_key, addr, port);

    QByteArray conn0 = start0.GetConnectionId();

    EXPECT_EQ(Packet::PacketType_TcpStart, start0.GetType());
    EXPECT_EQ(verif_key, start0.GetVerificationKey());
    ASSERT_FALSE(start0.UsesHostName());

    EXPECT_EQ(addr, start0.GetHostAddress());
    EXPECT_EQ(port, start0.GetPort());

    QByteArray ser_start0 = start0.ToByteArray();

    int bytes_read = 0;
    QSharedPointer<Packet> pp0(Packet::ReadPacket(ser_start0, bytes_read));

    ASSERT_FALSE(pp0.isNull());
    ASSERT_EQ(ser_start0.count(), bytes_read);
    EXPECT_EQ(Packet::PacketType_TcpStart, pp0->GetType());
    EXPECT_EQ(conn0, pp0->GetConnectionId());

    TcpStartPacket* sp = dynamic_cast<TcpStartPacket*>(pp0.data());
    ASSERT_TRUE(sp);
    EXPECT_EQ(Packet::PacketType_TcpStart, sp->GetType());
    EXPECT_EQ(verif_key, sp->GetVerificationKey());
    ASSERT_FALSE(sp->UsesHostName());
    EXPECT_EQ(addr, sp->GetHostAddress());
    EXPECT_EQ(port, sp->GetPort());
  }

  TEST(Packets, TcpStartPacketHostName)
  {
    QByteArray verif_key("verifverifverifverif");
    QByteArray hostn("absdsdlfkj.sdlkjhwefljk.sdfjh.net.ru");
    quint16 port = 12345;

    StartPacket start0(verif_key, hostn, port);

    QByteArray conn0 = start0.GetConnectionId();

    EXPECT_EQ(Packet::PacketType_Start, start0.GetType());
    EXPECT_EQ(verif_key, start0.GetVerificationKey());
    ASSERT_TRUE(start0.UsesHostName());

    EXPECT_EQ(hostn, start0.GetHostName());
    EXPECT_EQ(port, start0.GetPort());

    QByteArray ser_start0 = start0.ToByteArray();

    int bytes_read = 0;
    QSharedPointer<Packet> pp0(Packet::ReadPacket(ser_start0, bytes_read));

    ASSERT_FALSE(pp0.isNull());
    ASSERT_EQ(ser_start0.count(), bytes_read);
    EXPECT_EQ(Packet::PacketType_Start, pp0->GetType());
    EXPECT_EQ(conn0, pp0->GetConnectionId());

    StartPacket* sp = dynamic_cast<StartPacket*>(pp0.data());
    ASSERT_TRUE(sp);
    EXPECT_EQ(Packet::PacketType_Start, sp->GetType());
    EXPECT_EQ(verif_key, sp->GetVerificationKey());
    ASSERT_TRUE(sp->UsesHostName());
    EXPECT_EQ(hostn, sp->GetHostName());
    EXPECT_EQ(port, sp->GetPort());
  }
  */
}
}
