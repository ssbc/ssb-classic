// SPDX-FileCopyrightText: 2022 Andre 'Staltz' Medeiros <contact@staltz.com>
//
// SPDX-License-Identifier: CC0-1.0

const test = require('tape');
const ssbKeys = require('ssb-keys');
const {check} = require('ssb-feed-format');

const format = require('../format');

test('passes ssb-feed-format', (t) => {
  t.doesNotThrow(() => {
    check(format, ssbKeys.generate);
  });
  t.end();
});

test('newNativeMsg output must pass validate()', (t) => {
  const keys = ssbKeys.generate();
  const nativeMsg = format.newNativeMsg({
    keys,
    content: {
      type: 'post',
      text: 'Hello, world!',
    },
    timestamp: Date.now(),
    previous: null,
    hmacKey: null,
  });
  format.validate(nativeMsg, null, null, (err) => {
    if (err) {
      t.fail(err);
    } else {
      t.pass('validation ok');
      t.end();
    }
  });
});
