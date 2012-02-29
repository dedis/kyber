#ifndef DISSENT_TESTS_OVERLAY_HELPER_H_GUARD
#define DISSENT_TESTS_OVERLAY_HELPER_H_GUARD

#include "DissentTest.hpp"
namespace Dissent {
namespace Tests {
  void SendTest(const QList<QSharedPointer<Node> > &nodes, bool live = false);
  void TerminateOverlay(const QList<QSharedPointer<Node> > &nodes, bool live = false);
}
}

#endif
