const mongoose = require('mongoose');

const message2Schema = new mongoose.Schema({
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
  text: {
    type: String,
    required: true,
    trim: true
  },
  timestamp: {
    type: String,
    required: true
  }
}, {
  collection: 'mensajes2'
});

module.exports = mongoose.model('message2', message2Schema);