const mongoose = require('mongoose');

let db2;

async function connectDB2() {
  try {
    db2 = await mongoose.createConnection('mongodb://127.0.0.1:27017/chatApp').asPromise();
    console.log('Conexión a MongoDB App 2 exitosa');
  } catch (error) {
    console.error('Error al conectar con MongoDB App 2:', error);
  }
}

function getDB2() {
  return db2;
}

module.exports = { connectDB2, getDB2 };