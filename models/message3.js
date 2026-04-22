const mongoose = require('mongoose');

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

module.exports = mongoose.model('Message3', message3Schema);