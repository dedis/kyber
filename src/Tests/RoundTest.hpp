#ifndef DISSENT_TESTS_ROUND_TEST_H_GUARD
#define DISSENT_TESTS_ROUND_TEST_H_GUARD

#include "TestNode.hpp"

#include <QByteArray>

namespace Dissent {
namespace Tests {
  typedef bool (*BadGuyCB)(Round *);

  inline void FlipByte(QByteArray &msg) {
    QScopedPointer<Random> rand(CryptoFactory::GetInstance().GetLibrary()->GetRandomNumberGenerator());

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

  typedef void(*SessionTestCallback)(SessionManager &sm);

  void RoundTest_Null(CreateSessionCallback callback,
      Group::SubgroupPolicy sg_policy);
  void RoundTest_Basic(CreateSessionCallback callback,
      Group::SubgroupPolicy sg_policy);
  void RoundTest_Basic_SessionTest(CreateSessionCallback callback, 
      Group::SubgroupPolicy sg_policy, SessionTestCallback session_cb);
  void RoundTest_MultiRound(CreateSessionCallback callback,
      Group::SubgroupPolicy sg_policy);
  void RoundTest_AddOne(CreateSessionCallback callback,
      Group::SubgroupPolicy sg_policy);
  void RoundTest_PeerDisconnectEnd(CreateSessionCallback callback,
      Group::SubgroupPolicy sg_policy);
  void RoundTest_PeerDisconnectMiddle(CreateSessionCallback callback,
      Group::SubgroupPolicy sg_policy, bool transient = false);
  void RoundTest_BadGuy(CreateSessionCallback good_callback,
      CreateSessionCallback bad_callback,
      Group::SubgroupPolicy sg_policy,
      const BadGuyCB &cb);
  void RoundTest_BadGuyBulk(CreateSessionCallback good_callback,
      CreateSessionCallback bad_callback,
      Group::SubgroupPolicy sg_policy,
      const BadGuyCB &cb);
  void RoundTest_BadGuyNoAction(CreateSessionCallback good_callback,
      CreateSessionCallback bad_callback, Group::SubgroupPolicy sg_policy,
      const BadGuyCB &cb);
}
}

#endif
