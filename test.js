const assert = require('assert');
const fs = require('fs');
const path = require('path');
const tap = require('tap');

const decrypt = require('./index.js');

// All the fixtures should decrypt to this key
let unenc = path.resolve(__dirname, 'fixtures', 'id_rsa_unencrypted');
unenc = Buffer.from(fs.readFileSync(unenc, 'ascii')
  .trim()
  .split('\n')
  .slice(1, -1)
  .join(''), 'base64');

let unencOpenSsh = path.resolve(__dirname, 'fixtures', 'id_rsa_open_unencrypted');
unencOpenSsh = Buffer.from(fs.readFileSync(unencOpenSsh, 'ascii')
  .trim()
  .split('\n')
  .slice(1, -1)
  .join(''), 'base64');

function tryThis(fn, f, msg) {
  tap.test(f, (t) => {
    t.plan(1);
    t.doesNotThrow(fn, msg);
  });
}

function test(fixture, unencryptedKey) {
  let file;
  let fileData;

  tryThis(() => {
    file = path.resolve(__dirname, 'fixtures', `id_rsa_${fixture}`);
    fileData = fs.readFileSync(file, 'ascii');
  }, fixture, 'failed reading test key');

  let data;
  tryThis(() => {
    assert(data = decrypt(fileData, 'asdf'));
    assert(Buffer.isBuffer(data), 'should be buffer');
  }, fixture, 'failed decryption');

  let hex;
  tryThis(() => {
    assert(hex = decrypt(fileData, 'asdf', 'hex'));
    assert.equal(typeof hex, 'string');
    assert.equal(hex, data.toString('hex'));
  }, fixture, 'failed hex decryption');

  let base64;
  tryThis(() => {
    assert(base64 = decrypt(fileData, 'asdf', 'base64'));
    assert.equal(typeof base64, 'string');
    assert.equal(base64, data.toString('base64'));
  }, fixture, 'failed base64 decryption');

  // OpenSSH encrypted keys aren't byte equivalent to unencrypted keys, can't directly compare
  if (unencryptedKey === unenc) {
    tryThis(() => {
      assert.equal(data.length, unencryptedKey.length);
    }, fixture, 'length differs');

    tryThis(() => {
      for (let i = 0; i < data.length; i++) {
        assert.equal(data[i], unencryptedKey[i], `differs at position ${i}`);
      }
    }, fixture, 'byte check');
  }
}

test('open_aes256-ctr_bcrypt_asdf', unencOpenSsh);
test('open_unencrypted', unencOpenSsh);

let tests = [
  'aes128',
  'aes192',
  'aes256',
  'des3',
  'des',
];

tests = tests.map((t) => `enc_${t}_asdf`);

tests.push('unencrypted');

tests.forEach(test, unenc);
