#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {
  TEST(KeyShare, Base)
  {
    KeyShare ks;
    Hash hash;
    QList<QString> names;
    QHash<QString, QSharedPointer<AsymmetricKey> > keys;

    QString rel_path = QString::number(Utils::Random::GetInstance().GetInt());
    while(QDir::temp().exists(rel_path)) {
      rel_path = QString::number(Utils::Random::GetInstance().GetInt());
    }

    QDir::temp().mkpath(rel_path);
    ASSERT_TRUE(QDir::temp().exists(rel_path));
    QString base_path = QDir::tempPath() + QDir::separator() + rel_path + QDir::separator();

    for(int idx = 0; idx < 20; idx++) {
      QSharedPointer<AsymmetricKey> key(new DsaPrivateKey());
      QSharedPointer<AsymmetricKey> pkey(key->GetPublicKey());
      QString name(Utils::ToUrlSafeBase64(hash.ComputeHash(pkey->GetByteArray())));
      names.append(name);
      ks.AddKey(name, pkey);
      keys[name] = pkey;
      pkey->Save(base_path + name + ".pub");
    }

    KeyShare ks2(base_path);

    qSort(names);
    int idx = 0;
    foreach(const QSharedPointer<AsymmetricKey> &key, ks) {
      ASSERT_EQ(ks.GetKey(names[idx]), key);
      ASSERT_EQ(ks.GetKey(names[idx]), keys[names[idx]]);
      ASSERT_EQ(ks2.GetKey(names[idx]), key);
      idx++;
    }

    foreach(const QString &name, ks2.GetNames()) {
      ASSERT_TRUE(QDir::temp().remove(rel_path + QDir::separator() + name + ".pub"));
    }
    ASSERT_TRUE(QDir::temp().rmdir(rel_path));
    ASSERT_FALSE(QDir::temp().exists(rel_path));
  }
}
}
