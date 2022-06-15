// SPDX-FileCopyrightText: 2022 Andre 'Staltz' Medeiros <contact@staltz.com>
//
// SPDX-License-Identifier: CC0-1.0

const test = require('tape');
const dataset = require('ssb-validation-dataset');
const format = require('../format');

function makePrevious(datapoint) {
  if (!datapoint.state) return null;
  return {
    previous: null,
    author: datapoint.message.author,
    sequence: datapoint.state.sequence,
    timestamp: datapoint.state.timestamp,
    hash: 'sha256',
    id: datapoint.state.id,
  };
}

dataset.forEach((datapoint, i) => {
  if (datapoint.valid) {
    test(`Message ${i} is valid`, (t) => {
      const msgVal = datapoint.message;
      const prevMsgVal = makePrevious(datapoint);
      const hmacKey = datapoint.hmacKey;
      format.validate(msgVal, prevMsgVal, hmacKey, (err) => {
        if (err) {
          console.log(datapoint);
          t.fail(err);
        } else t.end();
      });
    });
  } else {
    test(`Message ${i} is invalid: ${datapoint.error}`, (t) => {
      const msgVal = datapoint.message;
      const prevMsgVal = makePrevious(datapoint);
      const hmacKey = datapoint.hmacKey;
      format.validate(msgVal, prevMsgVal, hmacKey, (err) => {
        if (err) {
          if (err.message !== datapoint.error) {
            // console.warn(err.message, '!=', datapoint.error);
          }
          t.end();
        } else {
          console.log(datapoint);
          t.fail('Should have thrown error: ' + datapoint.error);
        }
      });
    });
  }
});
