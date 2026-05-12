const crypto = require('crypto');

function normalizeIdentity(value) {
  return String(value || '').trim().toLowerCase();
}

function getPepper() {
  const pepper = process.env.SECURITY_PEPPER;

  if (!pepper) {
    throw new Error('Falta SECURITY_PEPPER en .env');
  }

  return pepper;
}

function getEncryptionKey() {
  const keyHex = process.env.DATA_ENCRYPTION_KEY;

  if (!keyHex) {
    throw new Error('Falta DATA_ENCRYPTION_KEY en .env');
  }

  const key = Buffer.from(keyHex, 'hex');

  if (key.length !== 32) {
    throw new Error('DATA_ENCRYPTION_KEY debe tener 32 bytes en hex');
  }

  return key;
}

function hashIdentity(value) {
  return crypto
    .createHmac('sha256', getPepper())
    .update(normalizeIdentity(value))
    .digest('hex');
}

function hashInternalId(id) {
  return crypto
    .createHmac('sha256', getPepper())
    .update(String(id))
    .digest('hex');
}

function encryptIdentity(value) {
  const normalized = normalizeIdentity(value);
  const iv = crypto.randomBytes(12);
  const key = getEncryptionKey();

  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  const encrypted = Buffer.concat([
    cipher.update(normalized, 'utf8'),
    cipher.final()
  ]);

  const tag = cipher.getAuthTag();

  return {
    iv: iv.toString('base64'),
    ciphertext: encrypted.toString('base64'),
    tag: tag.toString('base64')
  };
}

function decryptIdentity(payload) {
  if (!payload || !payload.iv || !payload.ciphertext || !payload.tag) {
    return null;
  }

  const key = getEncryptionKey();
  const iv = Buffer.from(payload.iv, 'base64');
  const ciphertext = Buffer.from(payload.ciphertext, 'base64');
  const tag = Buffer.from(payload.tag, 'base64');

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);

  const decrypted = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final()
  ]);

  return decrypted.toString('utf8');
}

module.exports = {
  normalizeIdentity,
  hashIdentity,
  hashInternalId,
  encryptIdentity,
  decryptIdentity
};