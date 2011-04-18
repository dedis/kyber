/* libdissent/node_impl_bulk.hpp
   Dissent bulk send protocol node implementation.

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
#ifndef _DISSENT_LIBDISSENT_NODE_IMPL_BULK_HPP_
#define _DISSENT_LIBDISSENT_NODE_IMPL_BULK_HPP_ 1
#include <QByteArray>
#include <QList>

#include "config.hpp"
#include "node_impl.hpp"

namespace Dissent{
class NodeImplBulkSend;
namespace BulkSend{
    class MessageDescriptor{
      friend class ::Dissent::NodeImplBulkSend;
      public:
        MessageDescriptor(Configuration* config);

        void Initialize(const QByteArray& data);
        void Serialize(QByteArray* byte_array);
        void Deserialize(const QByteArray& byte_array);

      private:
        Configuration* _config;

        int _length;
        QByteArray _dataHash;
        QList<QByteArray> _checkSums;
        QList<QByteArray> _encryptedSeeds;

        // Privilege data
        QByteArray _xorData;
        QList<QByteArray> _seeds;

        static QByteArray EmptyStringHash;
    };
}  // namespace BulkSend

class NodeImplBulkSend : public NodeImpl{
  Q_OBJECT
  public:

    NodeImplBulkSend(Node* node,
                     const QByteArray& data,
                     const QList<BulkSend::MessageDescriptor>& descs);

    virtual bool StartProtocol(int round);
    virtual NodeImpl* GetNextImpl(Configuration::ProtocolVersion version);

  private slots:
    void CollectMulticasts(int node_id);

  private:
    void Blame(int slot);

    QByteArray _data;
    QList<BulkSend::MessageDescriptor> _descriptors;

    QList<QByteArray> _allData;
};
}
#endif  // _DISSENT_LIBDISSENT_NODE_IMPL_BULK_HPP_
// -*- vim:sw=4:expandtab:cindent:
