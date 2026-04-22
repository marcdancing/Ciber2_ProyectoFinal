const mongoose = require('mongoose');

let db3;

async function connectDB3() {
  try {
    db3 = await mongoose.createConnection('mongodb://127.0.0.1:27017/chatApp3').asPromise();
    console.log('Conexión a MongoDB App 3 exitosa');
  } catch (error) {
    console.error('Error al conectar con MongoDB App 3:', error);
  }
}

function getDB3() {
  return db3;
}

module.exports = { connectDB3, getDB3 };