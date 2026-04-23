const mongoose = require('mongoose');
const { getDB3 } = require('../db3');

const message3Schema = new mongoose.Schema({
  from: {
    type: String,
    required: true,
    trim: true
  },
  to: {
    type: String,
    required: true,
    trim: true
  },
  ciphertext: {
    type: String,
    required: true
  },
  iv: {
    type: String,
    required: true
  },
  authTag: {
    type: String,
    required: true
  },
  timestamp: {
    type: String,
    required: true
  }
}, {
  collection: 'mensajes3'
});

function getMessage3Model() {
  const db3 = getDB3();

  if (!db3) {
    throw new Error('La conexión db3 todavía no está inicializada');
  }

  return db3.models.Message3 || db3.model('Message3', message3Schema);
}

module.exports = getMessage3Model;