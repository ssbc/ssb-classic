// SPDX-FileCopyrightText: 2022 Andre 'Staltz' Medeiros <contact@staltz.com>
//
// SPDX-License-Identifier: CC0-1.0

const test = require('tape');
const format = require('../format');

test('ooo validation where signature is wrong', (t) => {
  const msgValInvalidSig = {
    previous: '%u5CkR2ik8jHMJFf0VY8STAY2+ou8C9kpRvmGOUEdr8A=.sha256',
    sequence: 2,
    author: '@dGm2+y3z0PCjt2Q08ruSFa7yh11g755dxZNjXWwxp90=.ed25519',
    timestamp: 1491901800000,
    hash: 'sha256',
    content: {type: 'test2'},
    signature:
      '/HAXhrhqHU6Zcmd3+CdiHgaoloXiVGPK3hB+6EiwoaMuC3PHv8TwfenWf8GIqptSrPJATyJfsdW1sMinqpirDA==.sig.ed25519',
  };

  format.validateOOO(msgValInvalidSig, null, (err) => {
    t.match(err.message, /invalid message: signature does not match/);
    t.end();
  });
});

test('ooo validation where previous is wrong', (t) => {
  const msgValMissingPrevious = {
    sequence: 2,
    author: '@dGm2+y3z0PCjt2Q08ruSFa7yh11g755dxZNjXWwxp90=.ed25519',
    timestamp: 1491901800000,
    hash: 'sha256',
    content: {type: 'test2'},
    signature:
      '/IGohrhqHU6Zcmd3+CdiHgaoloXiVGPK3hB+6EiwoaMuC3PHv8TwfenWf8GIqptSrPJATyJfsdW1sMinqpirDA==.sig.ed25519',
  };

  format.validateOOO(msgValMissingPrevious, null, (err) => {
    t.match(err.message, /invalid message: must have previous/);
    t.end();
  });
});