#include <QDebug>

#include "Utils/QRunTimeError.hpp"
#include "Crypto/CryptoFactory.hpp"

#include "ShuffleBlamer.hpp"

using Dissent::Utils::QRunTimeError;
using Dissent::Crypto::CryptoFactory;
using Dissent::Crypto::OnionEncryptor;

namespace Dissent {
namespace Anonymity {
  ShuffleBlamer::ShuffleBlamer(const Group &group,
      const Id &round_id,
      const QVector<Log> &logs,
      const QVector<QSharedPointer<AsymmetricKey> > &private_keys) :
    _group(group),
    _shufflers(group.GetSubgroup()),
    _logs(logs),
    _private_keys(private_keys),
    _bad_nodes(_group.Count(), false),
    _reasons(_group.Count()),
    _set(false)
  {
    for(int idx = 0; idx < _group.Count(); idx++) {
      QSharedPointer<AsymmetricKey> key;
      int sidx = _shufflers.GetIndex(_group.GetId(idx));
      if(sidx >= 0) {
        key = _private_keys[sidx];
      }
      _rounds.append(new ShuffleRoundBlame(_group, _group.GetId(idx),
            round_id, key));
    }
  }

  ShuffleBlamer::~ShuffleBlamer()
  {
    foreach(Round *round, _rounds) {
      delete round;
    }
  }

  void ShuffleBlamer::Set(const Id &id, const QString &reason)
  {
    Set(_group.GetIndex(id), reason);
  }

  void ShuffleBlamer::Set(int idx, const QString &reason)
  {
    qDebug() << "Blame:" << idx << ":" << reason;
    _bad_nodes[idx] = true;
    _reasons[idx].append(reason);
    _set = true;
  }

  void ShuffleBlamer::Start()
  {
    qDebug() << "Blame: Parsing logs";
    ParseLogs();
    qDebug() << "Blame: Checking public keys";
    CheckPublicKeys();
    if(!_set) {
      qDebug() << "Blame: Checking shuffle / data";
      CheckShuffle();
    }

    if(!_set) {
      qDebug() << "Blame: Checking go / no go";
      CheckVerification();
    }
    qDebug() << "Blame: Done";
  }

  const QVector<QString> &ShuffleBlamer::GetReasons(int idx)
  {
    return _reasons[idx];
  }

  void ShuffleBlamer::ParseLogs()
  {
    for(int idx = 0; idx < _logs.count(); idx++) {
      ParseLog(idx);
    }
  }

  void ShuffleBlamer::ParseLog(int idx)
  {
    Log &clog = _logs[idx];
    ShuffleRoundBlame *round = _rounds[idx];
    round->Start();

    for(int jdx = 0; jdx < clog.Count(); jdx++) {
      QPair<QByteArray, Id> entry = clog.At(jdx);

      try {
        round->ProcessData(entry.second, entry.first);
      } catch (QRunTimeError &err) {
        qWarning() << idx << "received a message from" <<
          _group.GetIndex(entry.second) << "in state" <<
          ShuffleRound::StateToString(round->GetState()) <<
          "causing the following exception: " << err.What();
        Set(idx, err.What());
      }
    }
  }

  void ShuffleBlamer::CheckPublicKeys()
  {
    // First fine the first good peer and also mark all the bad peers
    int first_good = -1;
    for(int idx = 0; idx < _rounds.count(); idx++) {
      if(_rounds[idx]->GetState() == ShuffleRound::KEY_SHARING) {
        Set(idx, "Missing key log entries");
      }
      if(first_good == -1) {
        first_good = idx;
      }
    }

    QVector<QSharedPointer<AsymmetricKey> > inner_keys = _rounds[first_good]->GetPublicInnerKeys();
    QVector<QSharedPointer<AsymmetricKey> > outer_keys = _rounds[first_good]->GetPublicOuterKeys();
    if(inner_keys.count() != outer_keys.count()) {
      qCritical() << "Key sizes don't match";
    }

    for(int idx = 0; idx < _shufflers.Count(); idx++) {
      if(idx == first_good) {
        continue;
      }

      if(_rounds[idx]->GetState() == ShuffleRound::KEY_SHARING) {
        continue;
      }

      int sidx = _shufflers.GetIndex(_group.GetId(idx));
      if(sidx >= 0) {
        QSharedPointer<AsymmetricKey> p_outer_key = _rounds[idx]->GetPrivateOuterKey();
        if(!p_outer_key->IsValid()) {
          Set(idx, "Invalid private key");
          continue;
        }

        int kdx = _rounds[0]->CalculateKidx(sidx);
        if(!p_outer_key->VerifyKey(*(outer_keys[kdx]))) {
          Set(idx, "Mismatched private key");
        }
      }

      QVector<QSharedPointer<AsymmetricKey> > cinner_keys = _rounds[idx]->GetPublicInnerKeys();
      QVector<QSharedPointer<AsymmetricKey> > couter_keys = _rounds[idx]->GetPublicOuterKeys();

      if(inner_keys.count() != cinner_keys.count() || 
          outer_keys.count() != couter_keys.count()) {
        qCritical() << "Peers keys count don't match";
      }

      for(int jdx = 0; jdx < cinner_keys.count(); jdx++) {
        // Note public keys are kept in reverse order...
        int kdx = _rounds[0]->CalculateKidx(jdx);
        // If a node has passed KeySharing, then all messasges are validated and
        // any "suprise" keys were introduced by the provider of the key
        if(*(inner_keys[kdx]) == *(cinner_keys[kdx]) &&
            *(outer_keys[kdx]) == *(couter_keys[kdx])) {
          continue;
        }

        Set(jdx, "Bad public keys");
      }
    }
  }

  void ShuffleBlamer::CheckShuffle()
  {
    for(int gidx = 0; gidx < _group.Count(); gidx++) {
      if(_rounds[gidx]->GetState() == ShuffleRound::BLAME_SHARE) {
        continue;
      }

      Set(gidx, "Wrong state");
    }

    // If any failures ... let's not try to deal with the logic at this point...
    if(_set) {
      return;
    }

    _inner_data = _rounds[_group.GetIndex(_shufflers.GetId(0))]->GetShuffleCipherText();

    OnionEncryptor &oe = CryptoFactory::GetInstance().GetOnionEncryptor();
    for(int idx = 0; idx < _private_keys.count(); idx++) {
      QVector<QByteArray> outdata;
      QVector<int> bad;
      oe.Decrypt(_private_keys[idx], _inner_data, outdata, &bad);
      _inner_data = outdata;
      if(bad.count() == 0) {
        continue;
      }
      foreach(int bidx, bad) {
        Set(bidx, "Invalid crypto data");
      }
    }

    if(_set) {
      return;
    }

    // Check intermediary steps
    for(int idx = 0; idx < _shufflers.Count() - 1; idx++) {
      int pidx = _group.GetIndex(_shufflers.GetId(idx));
      int nidx = _group.GetIndex(_shufflers.GetId(idx + 1));

      const QVector<QByteArray> outdata = _rounds[pidx]->GetShuffleClearText();
      const QVector<QByteArray> indata = _rounds[nidx]->GetShuffleCipherText();
      
      if(CountMatches(outdata, indata) != _rounds.count()) {
        qDebug() << "Checking" << pidx << "output against" << nidx << "input: fail";
        Set(pidx, "Changed data");
        return;
      }
      qDebug() << "Checking" << pidx << "output against" << nidx << "input: success";
    }

    int last = _group.GetIndex(_shufflers.GetId(_shufflers.Count() - 1));
    QVector<QByteArray> calc_ic = _rounds[last]->GetShuffleClearText();

    for(int idx = 0; idx < _rounds.count(); idx++) {
      const QVector<QByteArray> recv_ic = _rounds[idx]->GetEncryptedData();
      if(recv_ic.count() == 0) {
        continue;
      }
      if(CountMatches(calc_ic, recv_ic) != _rounds.count()) {
        Set(last, "Changed final data");
        return;
      }
    }
  }

  int ShuffleBlamer::CountMatches(const QVector<QByteArray> &lhs, const QVector<QByteArray> &rhs)
  {
    int matches = 0;
    foreach(const QByteArray &data, lhs) {
      if(rhs.contains(data)) {
        matches++;
      }
    }
    return matches;
  }

  void ShuffleBlamer::CheckVerification()
  {
    QBitArray go(_rounds.count(), false);
    QBitArray go_found(_rounds.count(), false);

    for(int idx = 0; idx < _rounds.count(); idx++) {
      ShuffleRoundBlame *psrb = _rounds[idx];
      for(int jdx = 0; jdx < _rounds.count(); jdx++) {
        int go_val = psrb->GetGo(jdx);
        if(go_val == 0) {
          continue;
        } else if(go_found[jdx]) {
          if((go[jdx] && (go_val == 1)) || (!go[jdx] && (go_val == -1))) {
            continue;
          }
          Set(jdx, "Different go states different nodes");
        } else {
          go[jdx] = go_val == 1 ? true : false;
          go_found[jdx] = true;
        }
      }
    }

    int first = _group.GetIndex(_shufflers.GetId(0));
    QVector<QByteArray> ciphertext = _rounds[first]->GetShuffleCipherText();
    int last = _group.GetIndex(_shufflers.GetId(_shufflers.Count() - 1));
    QVector<QByteArray> cleartext = _rounds[last]->GetShuffleClearText();

    for(int idx = 0; idx < _rounds.count(); idx++) {
      bool good = cleartext.contains(_inner_data[idx]);
      if(!go_found[idx] || (!good && !go[idx]) || (good && go[idx])) {
        continue;
      }
      Set(idx, "Bad go");
    }
  }
}
}
