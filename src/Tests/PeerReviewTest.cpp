#include "DissentTest.hpp"

using namespace Dissent::PeerReview;

namespace Dissent {
namespace Tests {
  QSharedPointer<Entry> CreateSendEntry(QSharedPointer<AsymmetricKey> key)
  {
    CryptoRandom rand;
    Hash hash;
    uint seq_id = rand.GetInt();
    Id id;

    QByteArray previous_hash(hash.GetDigestSize(), 0);
    rand.GenerateBlock(previous_hash);

    QByteArray msg(1024, 0);
    rand.GenerateBlock(msg);

    QSharedPointer<Entry> entry(new SendEntry(seq_id, id, previous_hash, msg));
    entry->Sign(key);
    return entry;
  }

  QSharedPointer<Entry> CreateReceiveEntry(QSharedPointer<AsymmetricKey> key,
      QSharedPointer<Entry> send_entry)
  {
    CryptoRandom rand;
    Hash hash;

    uint seq_id = rand.GetInt();
    Id id;
    QByteArray previous_hash(hash.GetDigestSize(), 0);
    rand.GenerateBlock(previous_hash);

    QSharedPointer<SendEntry> se = send_entry.dynamicCast<SendEntry>();
    QSharedPointer<Entry> re(new ReceiveEntry(seq_id, id, previous_hash, se));
    re->Sign(key);
    return re;
  }

  TEST(PeerReview, SendEntry)
  {
    QSharedPointer<AsymmetricKey> key(new DsaPrivateKey());
    QSharedPointer<Entry> entry = CreateSendEntry(key);
    QSharedPointer<Entry> entry0 = ParseEntry(entry->Serialize());

    ASSERT_TRUE(entry0->Verify(key));
    ASSERT_EQ(*entry.data(), *entry0.data());
  }

  TEST(PeerReview, ReceiveEntry)
  {
    QSharedPointer<AsymmetricKey> key0(new DsaPrivateKey());
    QSharedPointer<AsymmetricKey> key1(new DsaPrivateKey());

    QSharedPointer<Entry> se = CreateSendEntry(key0);
    QSharedPointer<Entry> re = CreateReceiveEntry(key1, se);
    QSharedPointer<ReceiveEntry> rre = re.dynamicCast<ReceiveEntry>();
    ASSERT_EQ(*(rre->GetSendEntry().data()), *se.data());

    QSharedPointer<Entry> se0 = ParseEntry(se->Serialize());
    QSharedPointer<SendEntry> sse = se0.dynamicCast<SendEntry>();
    QSharedPointer<Entry> re0 = ParseEntry(re->Serialize());

    ASSERT_EQ(*re.data(), *re0.data());
    ASSERT_EQ(*se.data(), *se0.data());

    QSharedPointer<Entry> entry = re0.dynamicCast<ReceiveEntry>()->GetSendEntry();

    ASSERT_TRUE(re0->Verify(key1));
    ASSERT_FALSE(re0->Verify(key0));
    ASSERT_TRUE(se->Verify(key0));
    ASSERT_TRUE(se0->Verify(key0));
    ASSERT_TRUE(re0.dynamicCast<ReceiveEntry>()->GetSendEntry()->Verify(key0));
    ASSERT_FALSE(re0.dynamicCast<ReceiveEntry>()->GetSendEntry()->Verify(key1));
  }

  TEST(PeerReview, Acknowledgement)
  {
    QSharedPointer<AsymmetricKey> key0(new DsaPrivateKey());
    QSharedPointer<AsymmetricKey> key1(new DsaPrivateKey());

    QSharedPointer<Entry> se = CreateSendEntry(key0);
    QSharedPointer<Entry> re = CreateReceiveEntry(key1, se);
    QSharedPointer<ReceiveEntry> rre = re.dynamicCast<ReceiveEntry>();
    Acknowledgement ack(rre);
    QSharedPointer<Acknowledgement> ack0 = ParseEntry(ack.Serialize()).dynamicCast<Acknowledgement>();
    ASSERT_EQ(ack, *ack0.data());
    ASSERT_TRUE(ack.Verify(key1));
    ASSERT_TRUE(ack0->Verify(key1));
    ASSERT_TRUE(ack.VerifySend(se, key1));
    ASSERT_TRUE(ack0->VerifySend(se, key1));
    ASSERT_FALSE(ack.VerifySend(se, key0));
    ASSERT_FALSE(ack0->VerifySend(re, key1));
  }

  TEST(PeerReview, EntryLog)
  {
    QSharedPointer<AsymmetricKey> key0(new DsaPrivateKey());
    QSharedPointer<AsymmetricKey> key1(new DsaPrivateKey());
    CryptoRandom rand;
    Hash hash;
    Id id0, id1;

    QByteArray previous_hash(hash.GetDigestSize(), 0);
    rand.GenerateBlock(previous_hash);
    EntryLog log(previous_hash);

    for(int idx = 0; idx < 100; idx++) {
      QByteArray msg(1024, 0);
      rand.GenerateBlock(msg);

      double rand_val = ((double) rand.GetInt(0, 1000)) / 1000.0;
      if(rand_val < .5) {
        QSharedPointer<SendEntry> entry(
            new SendEntry(log.PreviousSequenceId(),
              id1, log.PreviousHash(), msg));
        entry->Sign(key0);
        log.AppendEntry(entry);
        continue;
      }

      rand.GenerateBlock(previous_hash);
      QSharedPointer<SendEntry> se(
          new SendEntry(idx, id0, previous_hash, msg));
      se->Sign(key1);

      QSharedPointer<Entry> entry(
          new ReceiveEntry(log.PreviousSequenceId(),
            id1, log.PreviousHash(), se));
      entry->Sign(key0);
      log.AppendEntry(entry);
    }

    QByteArray binary_log = log.Serialize();
    EntryLog log0 = EntryLog::ParseLog(binary_log);

    uint seq_id = -1;
    previous_hash = log.BaseHash();

    foreach(const QSharedPointer<Entry> &entry, log0) {
      uint n_seq_id = entry->GetSequenceId();
      QByteArray next_hash = entry->GetPreviousHash();

      ASSERT_TRUE(seq_id < entry->GetSequenceId());
      ASSERT_EQ(previous_hash, next_hash);
      ASSERT_TRUE(entry->Verify(key0));

      if(entry->GetType() == Entry::RECEIVE) {
        QSharedPointer<ReceiveEntry> re = entry.dynamicCast<ReceiveEntry>();
        re->GetSendEntry()->Verify(key1);
      }

      seq_id = n_seq_id;
      previous_hash = next_hash;
    }
  }

  TEST(PeerReview, PeerReview)
  {
    CryptoRandom rand;

    PrivateIdentity cred0(Id(),
          QSharedPointer<AsymmetricKey>(new DsaPrivateKey()),
          QSharedPointer<AsymmetricKey>(new RsaPrivateKey()),
          DiffieHellman());

    PrivateIdentity cred1(Id(),
          QSharedPointer<AsymmetricKey>(new DsaPrivateKey()),
          QSharedPointer<AsymmetricKey>(new RsaPrivateKey()),
          DiffieHellman());

    Group group;
    group = AddGroupMember(group, GetPublicIdentity(cred0));
    group = AddGroupMember(group, GetPublicIdentity(cred1));

    PRManager pr0(cred0, group);
    PRManager pr1(cred1, group);

    QByteArray msg(1024, 0);
    for(int idx = 0; idx < 100; idx++) {
      PRManager *sender, *receiver;
      PrivateIdentity *c_sender, *c_receiver;

      double rand_val = ((double) rand.GetInt(0, 1000)) / 1000.0;
      if(rand_val < .5) {
        sender = &pr0;
        c_sender = &cred0;
        receiver = &pr1;
        c_receiver = &cred1;
      } else {
        receiver = &pr0;
        c_receiver = &cred0;
        sender = &pr1;
        c_sender = &cred1;
      }

      rand.GenerateBlock(msg);
      QByteArray packet, r_msg;
      uint seq_id;

      ASSERT_TRUE(sender->Send(msg, c_receiver->GetLocalId(), packet));
      ASSERT_TRUE(receiver->Receive(packet, c_sender->GetLocalId(), r_msg, seq_id));
      ASSERT_TRUE(receiver->Acknowledge(seq_id, packet));
      ASSERT_TRUE(sender->HandleAcknowledgement(packet, c_receiver->GetLocalId()));

      ASSERT_EQ(r_msg, msg);
    }

    EntryLog ent_log0, ent_log1;
    AcknowledgementLog ack_log0, ack_log1;
    ParseLogs(pr0.Serialize(), ent_log0, ack_log0);
    ParseLogs(pr1.Serialize(), ent_log1, ack_log1);

    ASSERT_EQ(ent_log0.Size(), ent_log1.Size());

    for(int idx = 0; idx < ent_log0.Size(); idx++) {
      QSharedPointer<SendEntry> sent;
      QSharedPointer<ReceiveEntry> received;
      QSharedPointer<Acknowledgement> ack;
      QSharedPointer<AsymmetricKey> s_key;
      QSharedPointer<AsymmetricKey> r_key;

      if(ent_log0.At(idx)->GetType() == Entry::SEND) {
        sent = ent_log0.At(idx).dynamicCast<SendEntry>();
        s_key = cred0.GetSigningKey();
        ack = ack_log0.At(sent->GetSequenceId());
        received = ent_log1.At(idx).dynamicCast<ReceiveEntry>();
        r_key = cred1.GetSigningKey();
      } else {
        received = ent_log0.At(idx).dynamicCast<ReceiveEntry>();
        r_key = cred0.GetSigningKey();
        sent = ent_log1.At(idx).dynamicCast<SendEntry>();
        s_key = cred1.GetSigningKey();
        ack = ack_log1.At(sent->GetSequenceId());
      }

      sent->Verify(s_key);
      received->Verify(r_key);
      received->GetSendEntry()->Verify(s_key);
      ASSERT_EQ(*sent.data(), *received->GetSendEntry());
      ASSERT_TRUE(ack->VerifySend(sent, r_key));
    }
  }
}
}
