#include <QDebug>

#include "ShuffleBlamer.hpp"
#include "../Crypto/OnionEncryptor.hpp"

namespace Dissent {
namespace Anonymity {
  ShuffleBlamer::ShuffleBlamer(const Group &group, const Id &session_id,
      const Id &round_id, const QVector<Log> &logs,
      const QVector<AsymmetricKey *> private_keys) :
    _group(group),
    _logs(logs),
    _private_keys(private_keys),
    _bad_nodes(_group.Count(), false),
    _reasons(_group.Count()),
    _set(false)
  {
    for(int idx = 0; idx < _group.Count(); idx++) {
      _rounds.append(new ShuffleRoundBlame(group, _group.GetId(idx), session_id,
            round_id, _private_keys[idx]));
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
      QByteArray data;
      Id remote;
      clog.At(jdx, data, remote);

      try {
        round->ProcessMessage(data, remote);
      } catch (QRunTimeError &err) {
        qWarning() << idx << "received a message from" <<
          _group.GetIndex(remote) << "in state" <<
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
      if(_rounds[idx]->GetState() == ShuffleRound::KeySharing) {
        Set(idx, "Missing key log entries");
      }
      if(first_good == -1) {
        first_good = idx;
      }
    }

    const QVector<AsymmetricKey *> inner_keys = _rounds[first_good]->GetPublicInnerKeys();
    const QVector<AsymmetricKey *> outer_keys = _rounds[first_good]->GetPublicOuterKeys();
    if(inner_keys.count() != outer_keys.count()) {
      qCritical() << "Key sizes don't match";
    }

    for(int idx = 0; idx < _group.Count(); idx++) {
      if(idx == first_good) {
        continue;
      }

      if(_rounds[idx]->GetState() == ShuffleRound::KeySharing) {
        continue;
      }

      const AsymmetricKey *p_outer_key = _rounds[idx]->GetPrivateOuterKey();
      if(!p_outer_key->IsValid()) {
        Set(idx, "Invalid private key");
        continue;
      }

      const QVector<AsymmetricKey *> cinner_keys = _rounds[idx]->GetPublicInnerKeys();
      const QVector<AsymmetricKey *> couter_keys = _rounds[idx]->GetPublicOuterKeys();

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


      int kdx = _rounds[0]->CalculateKidx(idx);
      if(!p_outer_key->VerifyKey(*(outer_keys[kdx]))) {
        Set(idx, "Mismatched private key");
      }
    }
  }

  void ShuffleBlamer::CheckShuffle()
  {
    int last_shuffle = -1;
    bool verified = false;
    for(int idx = 0; idx < _rounds.count() && !verified; idx++) {
      ShuffleRound::State cstate = _rounds[idx]->GetState();

      switch(cstate) {
        case ShuffleRound::Offline:
        case ShuffleRound::KeySharing:
        case ShuffleRound::DataSubmission:
        case ShuffleRound::WaitingForShuffle:
          break;
        case ShuffleRound::ShuffleDone:
          last_shuffle = idx;
          break;
        case ShuffleRound::Verification:
          last_shuffle = _rounds.count() - 1;
          verified = true;
          break;
        default:
          break;
      }
    }

    // First node misbehaved ... 
    if(last_shuffle == -1) {
      Set(0, "Never got shuffle data...");
    }

    // Verify all nodes are in their proper state...
    for(int idx = 0; idx <= last_shuffle; idx++) {
      ShuffleRound::State cstate = _rounds[idx]->GetState();

      switch(cstate) {
        case ShuffleRound::ShuffleDone:
        case ShuffleRound::Verification:
          continue;
        default:
          break;
      }
      Set(idx, "Another wrong state...");
    }

    // If any failures ... let's not try to deal with the logic at this point...
    if(_set) {
      return;
    }

    QVector<QByteArray> real_inner = _rounds[0]->GetShuffleCipherText();
    QVector<QByteArray> indata = real_inner;

    for(int idx = 0; idx < _private_keys.count(); idx++) {
      QVector<QByteArray> outdata;
      QVector<int> bad;
      OnionEncryptor::GetInstance().Decrypt(_private_keys[idx], indata, outdata, &bad);
      indata = outdata;
      if(bad.count() == 0) {
        continue;
      }
      foreach(int bidx, bad) {
        Set(bidx, "Invalid crypto data");
      }
    }

    // Check intermediary steps
    for(int idx = 0; idx < last_shuffle; idx++) {
      const QVector<QByteArray> outdata = _rounds[idx]->GetShuffleClearText();
      const QVector<QByteArray> indata = _rounds[idx + 1]->GetShuffleCipherText();
      
      if(indata.isEmpty()) {
        continue;
      }
      if(CountMatches(outdata, indata) != _rounds.count()) {
        Set(idx, "Changed data");
        return;
      }
    }

    if(last_shuffle != _rounds.count() - 1) {
      return;
    }

    // Check final step
    const QVector<QByteArray> outdata = _rounds.last()->GetShuffleClearText();
    if(outdata.isEmpty()) {
      Set(_rounds.count() - 1, "No final data");
      return;
    }

    for(int idx = 0; idx < _rounds.count(); idx++) {
      const QVector<QByteArray> indata = _rounds[idx]->GetEncryptedData();
      if(indata.count() == 0) {
        continue;
      }
      if(CountMatches(outdata, indata) != _rounds.count()) {
        Set(_rounds.count() - 1, "Changed final data");
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
          if((go[jdx] && (go_val == 1)) || (go[jdx] && (go_val == -1))) {
            continue;
          }
          Set(jdx, "Different go states different nodes");
        } else {
          go[jdx] = go_val == 1 ? true : false;
          go_found[jdx] = true;
        }
      }
    }

    QVector<QByteArray> cleartext = _rounds.last()->GetShuffleClearText();
    QVector<QByteArray> ciphertext = _rounds.first()->GetShuffleCipherText();
    QVector<QByteArray> calc_cleartext = ciphertext;

    foreach(AsymmetricKey *key, _private_keys) {
      QVector<QByteArray> tmp;
      OnionEncryptor::GetInstance().Decrypt(key, calc_cleartext, tmp, 0);
      calc_cleartext = tmp;
    }

    for(int idx = 0; idx < _rounds.count(); idx++) {
      bool good = cleartext.contains(calc_cleartext[idx]);
      if(!go_found[idx] || !(good ^ go[idx])) {
        continue;
      }
      Set(idx, "Bad go");
    }
  }
}
}
