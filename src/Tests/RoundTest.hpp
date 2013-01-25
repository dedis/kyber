#ifndef DISSENT_TESTS_ROUND_TEST_H_GUARD
#define DISSENT_TESTS_ROUND_TEST_H_GUARD

#include "TestNode.hpp"

#include <QByteArray>

namespace Dissent {
namespace Tests {
  typedef bool (*BadGuyCB)(Round *);

  inline void FlipByte(QByteArray &msg) {
    QScopedPointer<Random> rand(CryptoFactory::GetInstance().GetLibrary().GetRandomNumberGenerator());

    // Invert one byte
    const int idx = rand->GetInt(0, msg.count());
    msg[idx] = ~msg[idx];
  }

  template<typename T> bool TBadGuyCB(Round *pr)
  {
    T *pt = dynamic_cast<T *>(pr);
    if(pt) {
      return pt->Triggered();
    }
    return false;
  }

  template<template <int> class T, int N> bool TBadGuyCB(Round *pr)
  {
    T<N> *pt = dynamic_cast<T<N> *>(pr);
    if(pt) {
      return pt->Triggered();
    }
    return false;
  }

  template <template <int> class T, int N> QSharedPointer<Round> TNCreateRound(
      const Group &group, const PrivateIdentity &ident,
      const Dissent::Connections::Id &round_id,
      QSharedPointer<Dissent::Connections::Network> network,
      Dissent::Messaging::GetDataCallback &get_data)
  {
    QSharedPointer<Round> round(new T<N>(group, ident, round_id,
          network, get_data));
    round->SetSharedPointer(round);
    return round;
  }

  class RoundCollector : public QObject {
    Q_OBJECT

    public:
      QVector<QSharedPointer<Round> > rounds;

    public slots:
      void RoundFinished(const QSharedPointer<Round> &round)
      {
        rounds.append(round);
      }
  };

  typedef void(*SessionTestCallback)(SessionManager &sm);

  void RoundTest_Null(SessionCreator callback,
      Group::SubgroupPolicy sg_policy);
  void RoundTest_Basic(SessionCreator callback,
      Group::SubgroupPolicy sg_policy);
  void RoundTest_MultiRound(SessionCreator callback,
      Group::SubgroupPolicy sg_policy);
  void RoundTest_AddOne(SessionCreator callback,
      Group::SubgroupPolicy sg_policy);
  void RoundTest_PeerDisconnectEnd(SessionCreator callback,
      Group::SubgroupPolicy sg_policy);
  void RoundTest_PeerDisconnectMiddle(SessionCreator callback,
      Group::SubgroupPolicy sg_policy, bool transient = false);
  void RoundTest_BadGuy(SessionCreator good_callback,
      SessionCreator bad_callback,
      Group::SubgroupPolicy sg_policy,
      const BadGuyCB &cb);
  void RoundTest_BadGuyBulk(SessionCreator good_callback,
      SessionCreator bad_callback,
      Group::SubgroupPolicy sg_policy,
      const BadGuyCB &cb);
  void RoundTest_BadGuyNoAction(SessionCreator good_callback,
      SessionCreator bad_callback, Group::SubgroupPolicy sg_policy,
      const BadGuyCB &cb);
}
}

#endif
