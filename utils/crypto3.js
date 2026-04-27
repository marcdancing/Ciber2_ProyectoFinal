const crypto = require('crypto');

// Usa una clave de 32 bytes derivada de una passphrase
const SECRET = process.env.APP3_SECRET || 'v~Dx&/J.I+Inxo1xSbH`e>5!y[kb%d[W(R1ei£!G$H:6*59';
const KEY = crypto.createHash('sha256').update(SECRET).digest(); // 32 bytes

function encryptMessage(plainText) {
  const iv = crypto.randomBytes(12); // recomendado para GCM
  const cipher = crypto.createCipheriv('aes-256-gcm', KEY, iv);

  let encrypted = cipher.update(plainText, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  const authTag = cipher.getAuthTag();

  return {
    ciphertext: encrypted,
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex')
  };
}

function decryptMessage(ciphertext, iv, authTag) {
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    KEY,
    Buffer.from(iv, 'hex')
  );

  decipher.setAuthTag(Buffer.from(authTag, 'hex'));

  let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
}

module.exports = { encryptMessage, decryptMessage };