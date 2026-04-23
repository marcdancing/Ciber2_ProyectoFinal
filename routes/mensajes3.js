const express = require('express');
const router = express.Router();
const getMessage3Model = require('../models/message3');
const getUser3Model = require('../models/User3');
const { encryptMessage, decryptMessage } = require('../utils/crypto3');

function requireAuth3(req, res, next) {
  if (!req.session.user3) {
    req.session.error = 'Debes iniciar sesión para acceder a esta página';
    return res.redirect('/auth3/login');
  }
  next();
}

router.post('/chat/:username', requireAuth3, async (req, res) => {
  try {
    const Message3 = getMessage3Model();
    const otroUsuario = req.params.username;
    const text = req.body?.text?.trim();

    if (!text) {
      req.session.error = 'El mensaje no puede estar vacío';
      return res.redirect(`/message3/chat/${otroUsuario}`);
    }

    if (text.length > 200) {
      req.session.error = 'El mensaje no puede superar los 200 caracteres';
      return res.redirect(`/message3/chat/${otroUsuario}`);
    }

    const encrypted = encryptMessage(text);

    const nuevoMensaje = new Message3({
      from: req.session.user3.username,
      to: otroUsuario,
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      authTag: encrypted.authTag,
      timestamp: new Date().toLocaleString()
    });

    await nuevoMensaje.save();

    res.redirect(`/message3/chat/${otroUsuario}`);
  } catch (error) {
    console.error('ERROR EN POST /message3/chat/:username:', error);
    res.status(500).send('Error al enviar mensaje');
  }
});

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
    const otroUsuario = req.params.username;

    const mensajesDB = await Message3.find({
      $or: [
        { from: req.session.user3.username, to: otroUsuario },
        { from: otroUsuario, to: req.session.user3.username }
      ]
    }).sort({ _id: 1 });

    const mensajes = mensajesDB.map((msg) => {
      let text = '[Error al descifrar mensaje]';

      try {
        text = decryptMessage(msg.ciphertext, msg.iv, msg.authTag);
      } catch (e) {
        console.error('Error al descifrar:', e.message);
      }

      return {
        from: msg.from,
        to: msg.to,
        text,
        timestamp: msg.timestamp
      };
    });

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

// Enviar mensaje cifrado
router.get('/chat/:username', requireAuth3, async (req, res) => {
  try {
    const otroUsuario = req.params.username;
    console.log('Abriendo chat con:', otroUsuario);
    console.log('Usuario en sesión:', req.session.user3);

    const mensajesDB = await Message3.find({
      $or: [
        { from: req.session.user3.username, to: otroUsuario },
        { from: otroUsuario, to: req.session.user3.username }
      ]
    }).sort({ _id: 1 });

    console.log('Mensajes en BD:', mensajesDB);

    const mensajes = mensajesDB.map((msg) => {
      let text = '[Error al descifrar mensaje]';

      try {
        text = decryptMessage(msg.ciphertext, msg.iv, msg.authTag);
      } catch (e) {
        console.error('Error al descifrar mensaje:', e);
      }

      return {
        from: msg.from,
        to: msg.to,
        text,
        timestamp: msg.timestamp
      };
    });

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


module.exports = router;