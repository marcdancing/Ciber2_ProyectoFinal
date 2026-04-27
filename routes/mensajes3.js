const express = require('express');
const router = express.Router();
const getMessage3Model = require('../models/message3');
const getUser3Model = require('../models/User3');

function requireAuth3(req, res, next) {
  if (!req.session.user3) {
    req.session.error = 'Debes iniciar sesión para acceder a esta página';
    return res.redirect('/auth3/login');
  }
  next();
}

// Lista de usuarios disponibles
router.get('/inbox', requireAuth3, async (req, res) => {
  try {
    const User3 = getUser3Model();

    const usuarios = await User3.find({
      username: { $ne: req.session.user3.username }
    }).sort({ username: 1 });

    res.render('app3/inbox3', {
      title: 'Bandeja App 3',
      username: req.session.user3.username,
      usuarios
    });
  } catch (error) {
    console.error('ERROR EN /message3/inbox:', error);
    res.status(500).send('Error al cargar conversaciones');
  }
});

// Ver chat con un usuario concreto
router.get('/chat/:username', requireAuth3, async (req, res) => {
  try {
    const Message3 = getMessage3Model();
    const otroUsuario = req.params.username?.trim().toLowerCase();

    const mensajes = await Message3.find({
      $or: [
        { from: req.session.user3.username, to: otroUsuario },
        { from: otroUsuario, to: req.session.user3.username }
      ]
    }).sort({ _id: 1 });

    const error = req.session.error || null;
    req.session.error = null;

    res.render('app3/chat3', {
      title: `Chat con ${otroUsuario}`,
      username: req.session.user3.username,
      otroUsuario,
      mensajes,
      error
    });
  } catch (error) {
    console.error('ERROR EN /message3/chat/:username:', error);
    res.status(500).send('Error al cargar el chat');
  }
});

// Guardar mensaje ya cifrado desde cliente
router.post('/chat/:username', requireAuth3, async (req, res) => {
  try {
    const Message3 = getMessage3Model();
    const otroUsuario = req.params.username?.trim().toLowerCase();

    const {
      ciphertext,
      iv,
      encryptedKeyForRecipient,
      encryptedKeyForSender
    } = req.body;

    if (!ciphertext || !iv || !encryptedKeyForRecipient || !encryptedKeyForSender) {
      req.session.error = 'Faltan datos cifrados del mensaje';
      return res.redirect(`/message3/chat/${otroUsuario}`);
    }

    const nuevoMensaje = new Message3({
      from: req.session.user3.username,
      to: otroUsuario,
      ciphertext,
      iv,
      encryptedKeyForRecipient,
      encryptedKeyForSender,
      timestamp: new Date().toLocaleString()
    });

    console.log('BODY RECIBIDO APP3:', req.body);
    console.log('FROM:', req.session.user3.username);
    console.log('TO:', otroUsuario);
    await nuevoMensaje.save();
    console.log('MENSAJE CIFRADO GUARDADO:', nuevoMensaje);

    res.json({ ok: true });
  } catch (error) {
    console.error('ERROR EN POST /message3/chat/:username:', error);
    res.status(500).json({ error: 'Error al enviar mensaje' });
  }
});

module.exports = router;