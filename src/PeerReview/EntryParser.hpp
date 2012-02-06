#ifndef DISSENT_PEER_REVIEW_ENTRY_PARSER_H_GUARD
#define DISSENT_PEER_REVIEW_ENTRY_PARSER_H_GUARD

#include <QSharedPointer>
#include <QByteArray>

#include "Entry.hpp"

namespace Dissent {
namespace PeerReview {
  /**
   * Generalized parsing function
   */
  QSharedPointer<Entry> ParseEntry(const QByteArray &binary_entry);
}
}

#endif
