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
#include <QByteArray>
#include <QHash>
#include <QList>
#include <QSharedPointer>
#include <QString>

#include "dissent_global.hpp"
#include "config.hpp"
#include "node_impl.hpp"
#include "node_impl_shuffle.hpp"
#include "random_util.hpp"

namespace Dissent{
class NodeImplMultipleBulkSend;
namespace MultipleBulkSend{
    class BulkSendDescriptor{
      friend class ::Dissent::NodeImplMultipleBulkSend;
      public:
        BulkSendDescriptor(Configuration* config);

        void InitializeWithKeys(
                int round,
                const PrivateKey& session_key,
                const QHash<int, QSharedPointer<PublicKey> >& session_keys);
        void InitializeWithData(
                int round,
                const QByteArray& data,
                const QHash<int, QSharedPointer<PublicKey> >& session_keys);
        void Serialize(QByteArray* byte_array);
        void Deserialize(const QByteArray& byte_array);

        bool isPrivileged() const{ return !_seeds.isEmpty(); }

      private:
        static void InitializeStatic(Configuration* config);
        void InitializeSeeds(
                int round,
                const QHash<int, QSharedPointer<PublicKey> >& session_keys);

        Configuration* _config;

        QSharedPointer<PublicKey> _verifyKey;
        QList<QByteArray> _encryptedSeeds;
        QList<QByteArray> _seedHash;  // Is this needed?

        // Privilege data
        // Invariant:
        //   When isPrivileged():
        //        (_data.empty() || _signKey.isNull())
        //     && (_verifyKey.isNull() == _signKey.isNull())
        //   When !isPrivileged():
        //        (_data.empty() || _verifyKeys.isNull())
        //     && _signKey.isNull()
        QList<QByteArray> _seeds;
        QSharedPointer<PrivateKey> _signKey;
        QByteArray _data;

        static QByteArray EmptyStringHash;
    };
}  // namespace MultipleBulkSend

// Shuffle for version 2: bulk_desc includes encrypted seeds and the
// private key for message signatures
class NodeImplShuffleBulkDesc : public NodeImplShuffle{
  Q_OBJECT
  public:
    NodeImplShuffleBulkDesc(Node* node);

    virtual QString StepName() const;

  protected:
    virtual void GetShuffleData(QByteArray* data);

    virtual NodeImpl* GetNextImpl(Configuration::ProtocolVersion version);

  private:
    MultipleBulkSend::BulkSendDescriptor _desc;
};

class NodeImplMultipleBulkSend : public NodeImpl{
  Q_OBJECT
  public:
    typedef QList<MultipleBulkSend::BulkSendDescriptor> DescriptorList;
    NodeImplMultipleBulkSend(
            Node* node,
            PrivateKey* session_key,  // Take over ownership
            const QHash<int, QSharedPointer<PublicKey> >& session_keys,
            const DescriptorList& descs);

    virtual bool StartProtocol(int run);
    virtual QString StepName() const;

  protected:
    virtual NodeImpl* GetNextImpl(Configuration::ProtocolVersion version);

  private slots:
    void CollectMulticasts(int node_id);
    void StartRound();

  private:
    void UpdateDescriptors(int round, const DescriptorList& descs);
    Q_INVOKABLE void LengthInfoReady(const QList<QByteArray>& length_info);
    Q_INVOKABLE void DataReady(const QList<QByteArray>& data);

    void DoMultipleMulticast(
            const QList<int>& lengths,
            const QByteArray& to_send,
            const char* next_step);

    void Blame(int slot);
    void BlameNode(int node_id);

    int _round;
    int _round_limit;
    int _slot_position;
    QScopedPointer<PrivateKey> _session_key;
    QHash<int, QSharedPointer<PublicKey> > _session_keys;

    DescriptorList _descriptors;
    QList<QSharedPointer<PublicKey> > _verifyKeys;
    QList<QSharedPointer<PRNG> > _prngsForOthers;
    QList<QSharedPointer<PRNG> > _prngsForSelf;
    QSharedPointer<PrivateKey> _signKey;

    MultipleBulkSend::BulkSendDescriptor _nextDescriptor;
    QByteArray _toSend;

    // fields used by DoMultipleMulticast and CollectMulticasts
    QByteArray _toBroadcast;
    QList<int> _lengths;
    const char* _next_step;
    QList<QByteArray> _allData;
};
}
#endif  // _DISSENT_LIBDISSENT_NODE_IMPL_MULTIBULK_HPP_
// -*- vim:sw=4:expandtab:cindent:
