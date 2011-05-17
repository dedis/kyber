/* libdissent/node_impl_shuffle.hpp
   Dissent shuffle protocol node implementation.

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
#ifndef _DISSENT_LIBDISSENT_NODE_IMPL_SHUFFLE_HPP_
#define _DISSENT_LIBDISSENT_NODE_IMPL_SHUFFLE_HPP_ 1
#include <QByteArray>
#include <QHash>
#include <QScopedPointer>
#include <QSharedPointer>

#include "crypto.hpp"
#include "dissent_global.hpp"
#include "node_impl.hpp"

namespace Dissent{
class NodeImplShuffle : public NodeImpl{
  Q_OBJECT
  protected:
    NodeImplShuffle(Node* node) : NodeImpl(node), _toBlame(-1){}

  public:
    virtual bool StartProtocol(int round);

  protected:
    virtual void GetShuffleData(QByteArray* data) = 0;
    void GetShuffledData(QList<QByteArray>* data, int* position){
        if(data)
            *data = _shufflingData;
        if(position)
            *position = _myShuffledPosition;
    }

  private slots:
    void CollectOnetimeKeys(int node_id);
    void ReceiveShuffleData(int node_id);
    void CollectShuffleData(int node_id);
    void ReceiveFinalPermutation(int node_id);
    void CollectGoNg(int node_id);
    void CollectInnerKeys(int node_id);

  private:
    void DoDataSubmission();
    void DoAnonymization();
    void CheckPermutation(const QList<QByteArray>& permutation);
    void TryDecrypt(const QHash<int, QByteArray>& go_nogo_data);
    void DoDecryption(const QHash<int, QByteArray>& inner_key_data);

    // the length of chunks are all the same, returns true if that's
    // the case
    static bool QByteArrayToPermutation(
            const QByteArray& byte_array,
            QList<QByteArray>* permutation);
    static void PermutationToQByteArray(
            const QList<QByteArray>& permutation,
            QByteArray* byte_array);

    static const char* const GoMsgHeader;
    static const char* const NoGoMsgHeader;

    // TODO(scw): we probably need extra information
    void Blame(int node_id);

    int _toBlame;

    QScopedPointer<PrivateKey> _innerKey;
    QScopedPointer<PrivateKey> _outerKey;
    QHash<int, QSharedPointer<PublicKey> > _innerKeys;
    QHash<int, QSharedPointer<PublicKey> > _outerKeys;

    QList<QByteArray> _randomness;
    QByteArray _innerOnionEncryptedData;

    // XXX(scw): used by both CollectShuffleData, CollectGoNg, and
    //           CollectInnerKeys
    QHash<int, QByteArray> _dataCollected;

    QList<QByteArray> _shufflingData;
    int _myShuffledPosition;
};

class NodeImplShuffleOnly : public NodeImplShuffle{
  Q_OBJECT
  public:
    NodeImplShuffleOnly(Node* node);

  protected:
    virtual void GetShuffleData(QByteArray* data);

    virtual NodeImpl* GetNextImpl(Configuration::ProtocolVersion version);

  private:
    QByteArray _data;
};
}
#endif  // _DISSENT_LIBDISSENT_NODE_IMPL_SHUFFLE_HPP_
// -*- vim:sw=4:expandtab:cindent:
