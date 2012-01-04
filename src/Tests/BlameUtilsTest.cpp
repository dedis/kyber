#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {

  typedef Dissent::Anonymity::Tolerant::Accusation Accusation;
  typedef Dissent::Anonymity::Tolerant::AlibiData AlibiData;
  typedef Dissent::Anonymity::Tolerant::BlameMatrix BlameMatrix;
  typedef Dissent::Anonymity::Tolerant::Conflict Conflict;
  typedef Dissent::Anonymity::Tolerant::MessageHistory MessageHistory;

  TEST(BlameUtils, Accusation_Basic) {
    Accusation a0;
    ASSERT_FALSE(a0.IsInitialized());

    a0.SetData(1, 3, 1);
    ASSERT_TRUE(a0.IsInitialized());

    a0.SetData(1, 3, 7);
    ASSERT_TRUE(a0.IsInitialized());
    ASSERT_EQ(1u, a0.GetPhase());
    ASSERT_EQ(3u, a0.GetByteIndex());
    ASSERT_EQ(0, a0.GetBitIndex());

    QByteArray bytes = a0.ToByteArray();

    Accusation a1;
    ASSERT_TRUE(a1.FromByteArray(bytes));
    ASSERT_TRUE(a1.IsInitialized());
    ASSERT_EQ(1u, a1.GetPhase());
    ASSERT_EQ(3u, a1.GetByteIndex());
    ASSERT_EQ(0, a1.GetBitIndex());
  }

  TEST(BlameUtils, AlibiData_Basic) {
    const uint nslots = 10;
    const uint nmembers = 5;
    AlibiData a(nslots, nmembers);

    // Phase 0
    a.NextPhase();

    // Phase 1
    a.NextPhase();

    // Phase 2
    a.NextPhase();

    QBitArray bits(nmembers, false);
    a.StorePhaseRngByteIndex(123);
    for(uint slot_idx=0; slot_idx<nslots; slot_idx++) {
      for(uint member_idx=0; member_idx<nmembers; member_idx++) {
        QByteArray b(2, slot_idx^member_idx);
        if(slot_idx == 2) {
          bits.setBit(member_idx, (slot_idx^member_idx)&(1<<3));
        }
        a.StoreMessage(2, slot_idx, member_idx, b);
      }
    }

    QByteArray bytes = a.GetAlibiBytes(2, 2, 1, 3);
   
    AlibiData a2(nslots, nmembers);
    QBitArray bits_out = a2.AlibiBitsFromBytes(bytes, 0, nmembers);

    ASSERT_EQ(bits, bits_out);

    // Save data from slot 1 and 2
    a.MarkSlotCorrupted(1);
    a.MarkSlotCorrupted(2);
   
    // Phase 3
    a.NextPhase();

    // Phase 4
    a.NextPhase();

    Accusation acc;
    acc.SetData(2, 1, 24);
    AlibiData a3(nslots, nmembers);
    QByteArray bytes2 = a.GetAlibiBytes(2, acc);
    QBitArray bits_out2 = a3.AlibiBitsFromBytes(bytes2, 0, nmembers);

    ASSERT_EQ(bits, bits_out2);

    ASSERT_EQ(125u, a.GetSlotRngByteOffset(2, 1));
    ASSERT_EQ(127u, a.GetSlotRngByteOffset(2, 2));
  }

  TEST(BlameUtils, BlameMatrix_OneByOne) {
    const uint nusers = 1;
    const uint nservers = 1;
    BlameMatrix b(nusers, nservers);

    QBitArray bits_true(1, true);
    QBitArray bits_false(1, false);

    b.AddUserAlibi(0, bits_true);
    b.AddServerAlibi(0, bits_true);

    b.AddUserOutputBit(0, true);
    b.AddServerOutputBit(0, true);

    QVector<int> bad_users;
    QVector<int> bad_servers;
    QList<Conflict> conflicts;

    bad_users = b.GetBadUsers();
    ASSERT_EQ(0, bad_users.count());

    bad_servers = b.GetBadServers();
    ASSERT_EQ(0, bad_servers.count());

    conflicts = b.GetConflicts(15);
    ASSERT_EQ(0, conflicts.count());

    // User sends wrong bit
    b.AddUserOutputBit(0, false);
    bad_users = b.GetBadUsers();
    ASSERT_EQ(1, bad_users.count());
    ASSERT_EQ(0, bad_users[0]);

    // Server sends wrong bit
    b.AddServerOutputBit(0, false);
    bad_servers = b.GetBadServers();
    ASSERT_EQ(1, bad_servers.count());
    ASSERT_EQ(0, bad_servers[0]);

    conflicts = b.GetConflicts(15);
    ASSERT_EQ(0, conflicts.count());

    // Server and user disagree on bit
    b.AddUserAlibi(0, bits_false);
    conflicts = b.GetConflicts(15);
    ASSERT_EQ(1, conflicts.count());
    
    Conflict con = conflicts[0];
    ASSERT_EQ(15u, con.GetSlotIndex());
    ASSERT_EQ(0u, con.GetUserIndex());
    ASSERT_FALSE(con.GetUserBit());
    ASSERT_EQ(0u, con.GetServerIndex());
    ASSERT_TRUE(con.GetServerBit());
  }

  void SetUpTestMatrix(BlameMatrix &b) {

    /*
              Users  
     Servers  0  1  2  3  4   OUT
           0  T  F  F  T  T = T
           1  F  F  T  F  T = F
           2  T  T  T  F  F = T
              =  =  =  =  = 
         OUT  F  T  F  T  F 
    */

    QBitArray bits_u0(3, false);
    bits_u0[0] = true;
    bits_u0[2] = true;

    QBitArray bits_u1(3, false);
    bits_u1[2] = true;

    QBitArray bits_u2(3, false);
    bits_u2[1] = true;
    bits_u2[2] = true;

    QBitArray bits_u3(3, false);
    bits_u3[0] = true;

    QBitArray bits_u4(3, false);
    bits_u4[0] = true;
    bits_u4[1] = true;

    QBitArray bits_s0(5, false);
    bits_s0[0] = true;
    bits_s0[3] = true;
    bits_s0[4] = true;

    QBitArray bits_s1(5, false);
    bits_s1[2] = true;
    bits_s1[4] = true;

    QBitArray bits_s2(5, false);
    bits_s2[0] = true;
    bits_s2[1] = true;
    bits_s2[2] = true;

    b.AddUserAlibi(0, bits_u0);
    b.AddUserAlibi(1, bits_u1);
    b.AddUserAlibi(2, bits_u2);
    b.AddUserAlibi(3, bits_u3);
    b.AddUserAlibi(4, bits_u4);

    b.AddServerAlibi(0, bits_s0);
    b.AddServerAlibi(1, bits_s1);
    b.AddServerAlibi(2, bits_s2);

    b.AddUserOutputBit(0, false);
    b.AddUserOutputBit(1, true);
    b.AddUserOutputBit(2, false);
    b.AddUserOutputBit(3, true);
    b.AddUserOutputBit(4, false);

    b.AddServerOutputBit(0, true);
    b.AddServerOutputBit(1, false);
    b.AddServerOutputBit(2, true);
    return;
  }

  TEST(BlameUtils, BlameMatrix_Clean) {
    const uint nusers = 5;
    const uint nservers = 3;
    BlameMatrix b(nusers, nservers);
    SetUpTestMatrix(b);

    QVector<int> bad_users;
    QVector<int> bad_servers;
    QList<Conflict> conflicts;

    bad_users = b.GetBadUsers();
    ASSERT_EQ(0, bad_users.count());

    bad_servers = b.GetBadServers();
    ASSERT_EQ(0, bad_servers.count());

    conflicts = b.GetConflicts(15);
    ASSERT_EQ(0, conflicts.count());
  }

  TEST(BlameUtils, BlameMatrix_BadUser) {
    const uint nusers = 5;
    const uint nservers = 3;
    BlameMatrix b(nusers, nservers);
    SetUpTestMatrix(b);


    QVector<int> bad_users;
    QVector<int> bad_servers;
    QList<Conflict> conflicts;

    bad_users = b.GetBadUsers();
    ASSERT_EQ(0, bad_users.count());

    // User 1 sends wrong bit
    b.AddUserOutputBit(1, false);
    bad_users = b.GetBadUsers();
    ASSERT_EQ(1, bad_users.count());
    ASSERT_EQ(1, bad_users[0]);

    // User 4 sends wrong bit
    b.AddUserOutputBit(4, true);
    bad_users = b.GetBadUsers();
    ASSERT_EQ(2, bad_users.count());
    ASSERT_EQ(1, bad_users[0]);
    ASSERT_EQ(4, bad_users[1]);

    conflicts = b.GetConflicts(15);
    ASSERT_EQ(0, conflicts.count());
  }

  TEST(BlameUtils, BlameMatrix_BadServer) {
    const uint nusers = 5;
    const uint nservers = 3;
    BlameMatrix b(nusers, nservers);
    SetUpTestMatrix(b);


    QVector<int> bad_users;
    QVector<int> bad_servers;
    QList<Conflict> conflicts;

    bad_users = b.GetBadUsers();
    ASSERT_EQ(0, bad_users.count());

    bad_servers = b.GetBadServers();
    ASSERT_EQ(0, bad_servers.count());

    // Server 2 sends wrong bit
    b.AddServerOutputBit(2, false);
    bad_servers = b.GetBadServers();
    ASSERT_EQ(1, bad_servers.count());
    ASSERT_EQ(2, bad_servers[0]);

    conflicts = b.GetConflicts(15);
    ASSERT_EQ(0, conflicts.count());
  }

  TEST(BlameUtils, BlameMatrix_Conflicts) {
    const uint nusers = 5;
    const uint nservers = 3;
    BlameMatrix b(nusers, nservers);
    SetUpTestMatrix(b);

    QVector<int> bad_users;
    QVector<int> bad_servers;
    QList<Conflict> conflicts;

    // Create a conflict between server 2, user 0
    QBitArray bits_s2(5, false);
    bits_s2[1] = true;
    bits_s2[2] = true;

    b.AddServerAlibi(2, bits_s2);
    b.AddServerOutputBit(2, false);

    bad_users = b.GetBadUsers();
    ASSERT_EQ(0, bad_users.count());

    bad_servers = b.GetBadServers();
    ASSERT_EQ(0, bad_servers.count());

    conflicts = b.GetConflicts(15);
    Conflict con = conflicts[0];
    ASSERT_EQ(15u, con.GetSlotIndex());
    ASSERT_EQ(0u, con.GetUserIndex());
    ASSERT_FALSE(con.GetServerBit());
    ASSERT_EQ(2u, con.GetServerIndex());
    ASSERT_TRUE(con.GetUserBit());
  }

  TEST(BlameUtils, MessageHistory_Basic) {
    const uint nusers = 10;
    const uint nservers = 5;
    MessageHistory hist(nusers, nservers);

    hist.NextPhase();
    hist.NextPhase();
    hist.NextPhase();
    const uint phase = 999;
    const uint slot = 8;
    for(uint user_idx=0; user_idx<nusers; user_idx++) {
      QByteArray msg(20, user_idx);
      hist.AddUserMessage(phase, slot, user_idx, msg);
    }

    for(uint server_idx=0; server_idx<nservers; server_idx++) {
      QByteArray msg(20, server_idx+93);
      hist.AddServerMessage(phase, slot, server_idx, msg);
    }

    Accusation acc;
    // Phase 999, slot 7, bit index 3
    acc.SetData(phase, 7, (1 << 3));

    for(uint user_idx=0; user_idx<nusers; user_idx++) {
      bool out = hist.GetUserOutputBit(slot, user_idx, acc);
      ASSERT_EQ((bool)((user_idx)&(1 << 3)), out);
    }

    for(uint server_idx=0; server_idx<nservers; server_idx++) {
      bool out = hist.GetServerOutputBit(slot, server_idx, acc);
      ASSERT_EQ((bool)((server_idx+93)&(1 << 3)), out);
    }
  }
}
}
