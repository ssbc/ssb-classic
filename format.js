// SPDX-FileCopyrightText: 2022 Andre 'Staltz' Medeiros
//
// SPDX-License-Identifier: LGPL-3.0-only

const Ref = require('ssb-ref');
const bipf = require('bipf');
const ssbKeys = require('ssb-keys');
const v = require('./validation');
const getMsgId = require('./get-msg-id');

const feedFormat = {
  name: 'classic',
  encodings: ['js', 'bipf'],

  getFeedId(nativeMsg) {
    return nativeMsg.author;
  },

  getMsgId,

  getSequence(nativeMsg) {
    return nativeMsg.sequence;
  },

  isNativeMsg(x) {
    return typeof x === 'object' && !!x && Ref.isFeedId(x.author);
  },

  isAuthor(author) {
    return Ref.isFeedId(author);
  },

  toPlaintextBuffer(opts) {
    return Buffer.from(JSON.stringify(opts.content), 'utf8');
  },

  newNativeMsg(opts) {
    const previous = opts.previous || {key: null, value: {sequence: 0}};
    const nativeMsg = {
      previous: previous.key,
      sequence: previous.value.sequence + 1,
      author: opts.keys.id,
      timestamp: +opts.timestamp,
      hash: 'sha256',
      content: opts.content,
    };
    let err;
    if ((err = v.validateContent(nativeMsg))) throw err;
    return ssbKeys.signObj(opts.keys, opts.hmacKey, nativeMsg);
  },

  fromNativeMsg(nativeMsg, encoding) {
    if (encoding === 'js') {
      return nativeMsg;
    } else if (encoding === 'bipf') {
      return bipf.allocAndEncode(nativeMsg);
    } else {
      // prettier-ignore
      throw new Error(`Feed format "${feedFormat.name}" does not support encoding "${encoding}"`)
    }
  },

  fromDecryptedNativeMsg(plaintextBuf, nativeMsg, encoding) {
    if (encoding === 'js') {
      const msgVal = nativeMsg;
      const content = JSON.parse(plaintextBuf.toString('utf8'));
      msgVal.content = content;
      return msgVal;
    } else if (encoding === 'bipf') {
      return bipf.allocAndEncode(
        feedFormat.fromDecryptedNativeMsg(plaintextBuf, nativeMsg, 'js'),
      );
    } else {
      // prettier-ignore
      throw new Error(`Feed format "${feedFormat.name}" does not support encoding "${encoding}"`)
    }
  },

  toNativeMsg(msg, encoding) {
    if (encoding === 'js') {
      return msg;
    } else if (encoding === 'bipf') {
      return bipf.decode(msg);
    } else {
      // prettier-ignore
      throw new Error(`Feed format "${feedFormat.name}" does not support encoding "${encoding}"`)
    }
  },

  _validateSync(nativeMsg, prevNativeMsg, hmacKey) {
    let err;
    if ((err = v.validateShape(nativeMsg))) return err;
    if ((err = v.validateHmac(hmacKey))) return err;
    if ((err = v.validateAuthor(nativeMsg))) return err;
    if ((err = v.validateHash(nativeMsg))) return err;
    if ((err = v.validateTimestamp(nativeMsg))) return err;
    if (prevNativeMsg) {
      if ((err = v.validatePrevious(nativeMsg, prevNativeMsg))) return err;
      if ((err = v.validateSequence(nativeMsg, prevNativeMsg))) return err;
    } else {
      if ((err = v.validateFirstPrevious(nativeMsg))) return err;
      if ((err = v.validateFirstSequence(nativeMsg))) return err;
    }
    if ((err = v.validateOrder(nativeMsg))) return err;
    if ((err = v.validateContent(nativeMsg))) return err;
    if ((err = v.validateAsJSON(nativeMsg))) return err;
    if ((err = v.validateSignature(nativeMsg, hmacKey))) return err;
  },

  _validateOOOSync(nativeMsg, hmacKey) {
    let err;
    if ((err = v.validateShape(nativeMsg))) return err;
    if ((err = v.validateHmac(hmacKey))) return err;
    if ((err = v.validateAuthor(nativeMsg))) return err;
    if ((err = v.validateHash(nativeMsg))) return err;
    if ((err = v.validateTimestamp(nativeMsg))) return err;
    if ((err = v.validateOrder(nativeMsg))) return err;
    if ((err = v.validateContent(nativeMsg))) return err;
    if ((err = v.validateAsJSON(nativeMsg))) return err;
    if ((err = v.validateSignature(nativeMsg, hmacKey))) return err;
  },

  validate(nativeMsg, prevNativeMsg, hmacKey, cb) {
    let err;
    if ((err = feedFormat._validateSync(nativeMsg, prevNativeMsg, hmacKey))) {
      return cb(err);
    }
    cb();
  },

  validateOOO(nativeMsg, hmacKey, cb) {
    let err;
    if ((err = feedFormat._validateOOOSync(nativeMsg, hmacKey))) {
      return cb(err);
    }
    cb();
  },

  validateBatch(nativeMsgs, prevNativeMsg, hmacKey, cb) {
    let err;
    let prev = prevNativeMsg;
    for (const nativeMsg of nativeMsgs) {
      err = feedFormat._validateSync(nativeMsg, prev, hmacKey);
      if (err) return cb(err);
      prev = nativeMsg;
    }
    cb();
  },

  validateOOOBatch(nativeMsgs, hmacKey, cb) {
    let err;
    for (const nativeMsg of nativeMsgs) {
      err = feedFormat._validateOOOSync(nativeMsg, hmacKey);
      if (err) return cb(err);
    }
    cb();
  },
};

module.exports = feedFormat;
