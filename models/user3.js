const mongoose = require('mongoose');
const { getDB3 } = require('../db3');

const encryptedFieldSchema = new mongoose.Schema({
  iv: { type: String, required: true },
  ciphertext: { type: String, required: true },
  tag: { type: String, required: true }
}, { _id: false });

const user3Schema = new mongoose.Schema({
  usernameHash: {
    type: String,
    required: true,
    unique: true,
    index: true
  },

  emailHash: {
    type: String,
    required: true,
    unique: true,
    index: true
  },

  usernameEncrypted: {
    type: encryptedFieldSchema,
    required: true
  },

  emailEncrypted: {
    type: encryptedFieldSchema,
    required: true
  },

  password: {
    type: String,
    required: true
  },

  publicKey: {
    type: String,
    default: null
  },

  mfaSecret: {
    type: String,
    default: null
  },

  mfaEnabled: {
    type: Boolean,
    default: false
  },

  certificateVersion: {
    type: Number,
    default: 1
  },

  certificateRevokedAt: {
    type: Date,
    default: null
  },

  certificateUpdatedAt: {
    type: Date,
    default: Date.now
  }
}, {
  collection: 'usuarios3'
});

function getUser3Model() {
  const db3 = getDB3();

  if (!db3) {
    throw new Error('La conexión db3 todavía no está inicializada');
  }

  return db3.models.User3 || db3.model('User3', user3Schema);
}

module.exports = getUser3Model;