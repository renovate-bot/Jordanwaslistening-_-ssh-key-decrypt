const nodeAssert = require('assert');
const bcryptPbkdf = require('bcrypt-pbkdf');
const crypto = require('crypto');
const util = require('util');

// Workaround https://github.com/electron/electron/issues/24577
const assert = {
  equal: (actual, expected) => {
    // eslint-disable-next-line eqeqeq
    if (actual != expected) {
      throw new nodeAssert.AssertionError({
        actual,
        expected,
        operator: '=='
      });
    }
  },
  ok: (value) => {
    if (!value) {
      throw new nodeAssert.AssertionError({
        actual: value,
        expected: true,
        operator: '=='
      });
    }
  }
};

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

const keyBytes = {
  'DES-EDE3-CBC': 24,
  'DES-CBC': 8,
  'AES-128-CBC': 16,
  'AES-192-CBC': 24,
  'AES-256-CBC': 32,
  'AES-128-CTR': 16,
  'AES-192-CTR': 24,
  'AES-256-CTR': 32,
};

const openSshMagicHeader = 'openssh-key-v1\0';
const openSshMagicHeaderBuffer = Buffer.from(openSshMagicHeader);

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

const decryptOpenSsh = (encData, key, iv, encryptionAlgorithm) => {
  const dec = crypto.createDecipheriv(encryptionAlgorithm, key, iv);
  dec.setAutoPadding(false);
  const result = [dec.update(encData), dec.final()];
  return Buffer.concat(result);
};

const bufferReadCString = (buffer, offset) => {
  const len = buffer.readInt32BE(offset[0]);
  offset[0] += 4;
  const result = buffer.subarray(offset[0], offset[0] + len);
  offset[0] += len;
  return result;
};

const bufferReadInt32 = (buffer, offset) => {
  const result = buffer.readInt32BE(offset[0]);
  offset[0] += 4;
  return result;
};

const bufferReadUInt32 = (buffer, offset) => {
  const result = buffer.readUInt32BE(offset[0]);
  offset[0] += 4;
  return result;
};

const parsePubKey = (buffer) => {
  const offset = [0];
  const keyType = bufferReadCString(buffer, offset).toString('ascii');
  if (keyType !== 'ssh-rsa') {
    return { keyType }; // parsing not supported unless ssh-rsa for now
  }
  const pub0 = bufferReadCString(buffer, offset).toString('ascii');
  const pub1 = bufferReadCString(buffer, offset).toString('base64');
  return { keyType, pub0, pub1 };
};

const parsePrivKey = (buffer, kdf, passphrase, encryptionAlgorithm) => {
  if (kdf !== null) {
    const keyLen = keyBytes[encryptionAlgorithm.toUpperCase()];
    const ivLen = 16; // aes iv is always 128 bits
    const keyIv = Buffer.alloc(keyLen + ivLen);
    const passBytes = Buffer.from(passphrase);
    const pbkdfResult = bcryptPbkdf.pbkdf(
      passBytes, passBytes.length, kdf.salt, kdf.salt.length, keyIv, keyIv.length, kdf.rounds
    );
    if (pbkdfResult !== 0) {
      throw new Error('Failed to derive pbkdf');
    }
    const key = keyIv.subarray(0, keyLen);
    const iv = keyIv.subarray(keyLen, keyLen + ivLen);
    buffer = decryptOpenSsh(buffer, key, iv, encryptionAlgorithm);
  }
  const offset = [0];
  const checkSum = [
    bufferReadUInt32(buffer, offset),
    bufferReadUInt32(buffer, offset)
  ];
  const checksumValid = checkSum[0] === checkSum[1];
  if (!checksumValid) {
    throw new Error('Private key checksum mismatch (wrong passphrase?)');
  }
  const keyType = bufferReadCString(buffer, offset).toString('ascii');
  if (keyType !== 'ssh-rsa') {
    return { parsed: { keyType }, raw: buffer }; // parsing not supported unless ssh-rsa for now
  }
  const pub0 = bufferReadCString(buffer, offset).toString('ascii');
  const pub1 = bufferReadCString(buffer, offset).toString('base64');
  const prv0 = bufferReadCString(buffer, offset).toString('ascii');
  // ...
  const comment = bufferReadCString(buffer, offset).toString('ascii');
  const parsed = {
    checkSum,
    keyType,
    pub0,
    pub1,
    prv0,
    comment
  };

  return {
    parsed,
    raw: buffer
  };
};

const parseKdf = (buffer) => {
  if (buffer.length === 0) {
    return null;
  }

  const offset = [0];
  const salt = bufferReadCString(buffer, offset);
  const rounds = bufferReadInt32(buffer, offset);
  assert.equal(buffer.length, offset);

  return {
    rounds,
    salt
  };
};

// OpenSSH keys are PEM encoded, however use a proprietary data format.
// Every data member is prefixed by a 32 bit length unless specified.
// "openssh-key-v1"0x00 (no length prefix)
// ciphername string
// kdfname string
// kdf packet (length == 0 if no kdf)
//    salt string
//    rounds uint32 (no length prefix)
// number of keys (hard-coded to 1, no length prefix)
// public key
//    key type string
//    pub0
//    pub1
// private key
//    2 32-bit uint32 checksum, equal if valid (after decryption, no length prefix)
//    key type string
//    pub0
//    pub1
//    prv0
//    comment
//    padding bytes
const parseOpenSshKey = (buffer, passphrase) => {
  const hasOpenSshMagicHeader = openSshMagicHeaderBuffer.compare(
    buffer, 0, openSshMagicHeaderBuffer.length
  ) === 0;
  assert.ok(hasOpenSshMagicHeader);
  const offset = [openSshMagicHeaderBuffer.length];
  let ciphername = bufferReadCString(buffer, offset).toString('ascii');
  if (ciphername !== 'none') {
    assert.ok(ciphername.startsWith('aes') && ['1', '2'].includes(ciphername[3]));
    ciphername = `${ciphername.slice(0, 3)}-${ciphername.slice(3)}`;
    assert.ok(ciphername.toUpperCase() in keyBytes);
  }
  const kdfname = bufferReadCString(buffer, offset).toString('ascii');
  assert.ok(kdfname === 'none' || kdfname === 'bcrypt');
  const kdfBytes = bufferReadCString(buffer, offset);
  const kdf = parseKdf(kdfBytes);
  const numKeys = bufferReadInt32(buffer, offset);
  assert.equal(1, numKeys);
  const pubKeyBytes = bufferReadCString(buffer, offset);
  const pubKey = parsePubKey(pubKeyBytes);
  const privKeyBytes = bufferReadCString(buffer, offset);
  const privKey = parsePrivKey(privKeyBytes, kdf, passphrase, ciphername);
  assert.equal(buffer.length, offset[0]);
  assert.equal(privKeyBytes.length, privKey.raw.length);
  for (let i = 0; i < privKeyBytes.length; ++i) {
    privKeyBytes[i] = privKey.raw[i];
  }

  return {
    privKey,
    pubKey,
    raw: buffer
  };
};

function main(data, passphrase, outEnc) {
  if (Buffer.isBuffer(data)) {
    data = data.toString('ascii');
  }

  if (!outEnc) {
    outEnc = 'buffer';
  }

  // Make sure it looks like a RSA or OpenSSH private key before moving forward
  const lines = data.trim().split('\n');
  const isRsa = lines[0] === '-----BEGIN RSA PRIVATE KEY-----'
    && lines[lines.length - 1] === '-----END RSA PRIVATE KEY-----';
  const isOpenSsh = lines[0] === '-----BEGIN OPENSSH PRIVATE KEY-----'
    && lines[lines.length - 1] === '-----END OPENSSH PRIVATE KEY-----';
  assert.ok(isRsa || isOpenSsh);

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
    let resultData = lines.slice(1, -1).join('');
    if (isOpenSsh) {
      const resultBuffer = Buffer.from(resultData, 'base64');
      const parsedKey = parseOpenSshKey(resultBuffer, passphrase);
      resultData = parsedKey.raw.toString('base64');
    }
    result = formatOut(resultData, outEnc);
  }

  return result;
}

module.exports = main;
