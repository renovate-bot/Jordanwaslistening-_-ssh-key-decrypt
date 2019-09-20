const util = require('util');

let debug;
if (util.debuglog) debug = util.debuglog('ssh-key-decrypt');
else if (/\bssh-key-decrypt\b/i.test(process.env.NODE_DEBUG || '')) {
  debug = (...args) => {
    // eslint-disable-next-line prefer-spread
    const msg = util.format(...args);
    // eslint-disable-next-line no-console
    console.error('%s %s', 'SSH-KEY-DECRYPT', msg);
  };
} else debug = () => {};

const crypto = require('crypto');
const assert = require('assert');

const keyBytes = {
  'DES-EDE3-CBC': 24,
  'DES-CBC': 8,
  'AES-128-CBC': 16,
  'AES-192-CBC': 24,
  'AES-256-CBC': 32,
};

function formatOut(data, outEnc) {
  let result;
  switch (outEnc) {
    case 'base64':
      result = data;
      break;

    case 'buffer':
      result = Buffer.from(data, 'base64');
      break;

    default:
      result = Buffer.from(data, 'base64').toString(outEnc);
      break;
  }
  return result;
}

// port of EVP_BytesToKey, as used when decrypting PEM keys
function passphraseToKey(type, passphrase, salt) {
  debug('passphraseToKey', type, passphrase, salt);
  let nkey = keyBytes[type];

  if (!nkey) {
    const allowed = Object.keys(keyBytes);
    throw new TypeError(`Unsupported type. Allowed: ${allowed}`);
  }

  let niv = salt.length;
  const saltLen = 8;
  if (salt.length !== saltLen) salt = salt.slice(0, saltLen);
  const mds = 16;
  let addmd = false;
  let mdBuf;
  const key = Buffer.alloc(nkey);
  let keyidx = 0;

  // eslint-disable-next-line no-constant-condition
  while (true) {
    debug('loop nkey=%d mds=%d', nkey, mds);
    const c = crypto.createHash('md5');

    if (addmd) c.update(mdBuf);
    else addmd = true;

    if (!Buffer.isBuffer(passphrase)) c.update(passphrase, 'ascii');
    else c.update(passphrase);

    c.update(salt);
    mdBuf = c.digest('buffer');

    let i = 0;
    while (nkey && i < mds) {
      key[keyidx++] = mdBuf[i];
      nkey--;
      i++;
    }

    const steps = Math.min(niv, mds - i);
    niv -= steps;
    i += steps;

    if ((nkey === 0) && (niv === 0)) break;
  }

  return key;
}

function decrypt(encData, type, passphrase, iv, outEnc) {
  debug('decrypt', type, outEnc);
  const key = passphraseToKey(type, passphrase, iv);
  const dec = crypto.createDecipheriv(type, key, iv);
  let data = '';
  data += dec.update(encData, 'base64', 'base64');
  data += dec.final('base64');
  return formatOut(data, outEnc);
}

function main(data, passphrase, outEnc) {
  if (Buffer.isBuffer(data)) {
    data = data.toString('ascii');
  }

  if (!outEnc) {
    outEnc = 'buffer';
  }

  // Make sure it looks like a RSA private key before moving forward
  const lines = data.trim().split('\n');
  assert.equal(lines[0], '-----BEGIN RSA PRIVATE KEY-----');
  assert.equal(lines[lines.length - 1], '-----END RSA PRIVATE KEY-----');

  let result;
  if (lines[1] === 'Proc-Type: 4,ENCRYPTED') {
    let dekInfo = lines[2];
    assert.equal(dekInfo.slice(0, 10), 'DEK-Info: ');
    dekInfo = dekInfo.slice(10).split(',');
    const type = dekInfo[0];
    const iv = Buffer.from(dekInfo[1], 'hex');
    assert.equal(lines[3], '');
    const encData = lines.slice(4, -1).join('');
    result = decrypt(encData, type, passphrase, iv, outEnc);
  } else {
    const resultData = lines.slice(1, -1).join('');
    result = formatOut(resultData, outEnc);
  }

  return result;
}

module.exports = main;
