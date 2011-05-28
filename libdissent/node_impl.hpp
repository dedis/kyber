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

#ifndef _DISSENT_LIBDISSENT_NODE_IMPL_HPP_
#define _DISSENT_LIBDISSENT_NODE_IMPL_HPP_ 1
#include <QObject>
#include <QString>

#include "config.hpp"
#include "dissent_global.hpp"

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
    virtual QString StepName() const = 0;

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

class NodeImplInitLeader : public NodeImpl{
  public:
    NodeImplInitLeader(Node* node) : NodeImpl(node){}

    virtual bool StartProtocol(int round);
    virtual QString StepName() const;

  protected:
    virtual NodeImpl* GetNextImpl(Configuration::ProtocolVersion version);
};

class NodeImplInit : public NodeImpl{
  Q_OBJECT
  public:
    NodeImplInit(Node* node, int leader_id)
        : NodeImpl(node), _leader_id(leader_id){}

    virtual bool StartProtocol(int round);
    virtual QString StepName() const;

  protected:
    virtual NodeImpl* GetNextImpl(Configuration::ProtocolVersion version);

  private slots:
    void Read(int node_id);

  private:
    int _round;
    int _leader_id;
};
}
#endif  // _DISSENT_LIBDISSENT_NODE_IMPL_HPP_
// -*- vim:sw=4:expandtab:cindent:
