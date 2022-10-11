// SPDX-FileCopyrightText: 2022 Mix Irving
//
// SPDX-License-Identifier: CC0-1.0

const test = require('tape');
const { validate } = require('../validation');

test('validate "too big"', (t) => {
  const Msg = (content) => ({
    previous: null,
    sequence: 1,
    author: '@someFeed00someFeed00someFeed00someFeed0011A=.ed25519',
    timestamp: 12312312312,
    hash: 'sha256',
    content,
    signature: '234234232334'
  })
  const msg1 = Msg({
    type: 'post',
    text: Array(10000).fill('!').join('')
  })
  const msg2 = Msg(Array(10000).fill('!').join('') + '.box2')

  validate(msg1, null, null, (err) => {
    t.match(
      err && err.message,
      /content must be at most 8192/,
      'plaintext oversized message invalid'
    )

    validate(msg2, null, null, (err) => {
      t.match(
        err && err.message,
        /content must be at most 8192/,
        'encrypted oversized message invalid'
      )
      t.end()
    })
  })
})
