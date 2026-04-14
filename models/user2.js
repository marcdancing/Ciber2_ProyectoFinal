const mongoose = require('mongoose');

const user2Schema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    trim: true
  },
  email: {
    type: String,
    required: true,
    trim: true
  },
  password: {
    type: String,
    required: true
  }
}, {
  collection: 'usuarios'
});

module.exports = mongoose.model('User2', user2Schema);