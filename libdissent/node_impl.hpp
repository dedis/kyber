/* libdissent/node_impl.hpp
   Dissent participant node base implementation.

   Author: Shu-Chun Weng <scweng _AT_ cs .DOT. yale *DOT* edu>
 */
/* ====================================================================
 * Dissent: Accountable Group Anonymity
 * Copyright (c) 2010 Yale University.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to
 *
 *   Free Software Foundation, Inc.,
 *   51 Franklin Street, Fifth Floor,
 *   Boston, MA  02110-1301  USA
 */

#ifndef _DISSENT_LIBDISSENT_NODE_IMPL_H_
#define _DISSENT_LIBDISSENT_NODE_IMPL_H_ 1

#include <QObject>

#include "config.hpp"

class QTimer;

namespace Dissent{
class Node;

class NodeImpl : public QObject{
  Q_OBJECT
  protected:
    NodeImpl(Node* node);

  public:
    // round is the number of times the whole protocol has been repeated.
    virtual bool StartProtocol(int round) = 0;
    virtual ~NodeImpl();

    static NodeImpl* GetInitLeader(Node* node);
    static NodeImpl* GetInit(Node* node, int leader_id);

  signals:
    void StepDone(NodeImpl* next_impl);
    void ProtocolFinished();

  protected slots:
    void ListenTimeout();

  protected:
    void StartListening(const char* slot, const QString& phase);
    void StopListening();

    void NextStep();
    virtual NodeImpl* GetNextImpl(Configuration::ProtocolVersion version) = 0;

    Node* _node;
    QTimer* _timeout_timer;

  private:
    const char* _listeningSlot;
};
}
#endif  // _DISSENT_LIBDISSENT_NODE_IMPL_H_
// -*- vim:sw=4:expandtab:cindent:
