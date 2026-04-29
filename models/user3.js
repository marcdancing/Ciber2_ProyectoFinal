const mongoose = require('mongoose');
const { getDB3 } = require('../db3');

const user3Schema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    trim: true,
    lowercase: true,
    unique: true
  },
  email: {
    type: String,
    required: true,
    trim: true,
    lowercase: true
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
    default:null
  },

  mfaEnabled: {
    type: Boolean,
    default: false
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