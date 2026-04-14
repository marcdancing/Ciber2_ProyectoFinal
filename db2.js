const mongoose = require('mongoose');

async function connectDB2() {
  try {
    await mongoose.connect('mongodb://127.0.0.1:27017/chatApp');
    console.log('Conexión a MongoDB exitosa');
  } catch (error) {
    console.error('Error al conectar con MongoDB:', error);
  }
}

module.exports = connectDB2;