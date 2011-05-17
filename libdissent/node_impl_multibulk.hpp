/* libdissent/node_impl_multibulk.hpp
   Dissent multiple bulk send protocol node implementation.

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
#ifndef _DISSENT_LIBDISSENT_NODE_IMPL_MULTIBULK_HPP_
#define _DISSENT_LIBDISSENT_NODE_IMPL_MULTIBULK_HPP_ 1
#include <QtGlobal>

#include "dissent_global.hpp"
#include "node_impl.hpp"
#include "node_impl_shuffle.hpp"

namespace Dissent{
class NodeImplMultipleBulkSend;
namespace MultipleBulkSend{
    class BulkSendDescriptor{
      friend class ::Dissent::NodeImplMultipleBulkSend;
      public:
        BulkSendDescriptor(Configuration* config);

        void Serialize(QByteArray* byte_array);
        void Deserialize(const QByteArray& byte_array);

        bool isPrivileged() const{ return !_seeds.isEmpty(); }

      private:
        Configuration* _config;

        QList<QByteArray> _encryptedSeeds;
        QList<QByteArray> _seedHash;  // Is this needed?
        PublicKey _verifyKey;

        // Privilege data
        QList<QByteArray> _seeds;
        PrivateKey _signKey;
    };
}  // namespace MultipleBulkSend

// Shuffle for version 2: bulk_desc includes encrypted seeds and the
// private key for message signatures
class NodeImplShuffleBulkDesc : public NodeImplShuffle{
  Q_OBJECT
  public:
    NodeImplShuffleBulkDesc(Node* node) : NodeImplShuffle(node){}

  protected:
    virtual void GetShuffleData(QByteArray* data);

    virtual NodeImpl* GetNextImpl(Configuration::ProtocolVersion version);
};

class NodeImplMultipleBulkSend : public NodeImpl{
  Q_OBJECT
  public:
    NodeImplMultipleBulkSend(
            Node* node,
            const QList<MultipleBulkSend::BulkSendDescriptor>& descs);

    virtual bool StartProtocol(int run);
    virtual NodeImpl* GetNextImpl(Configuration::ProtocolVersion version);

  private:
    void Blame(int slot);
    void BlameNode(int node_id);

    int _round;
    QList<MultipleBulkSend::BulkSendDescriptor> _descriptors;

    QList<QByteArray> _allData;
};
}
#endif  // _DISSENT_LIBDISSENT_NODE_IMPL_MULTIBULK_HPP_
// -*- vim:sw=4:expandtab:cindent:
