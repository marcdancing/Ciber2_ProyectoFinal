const express = require('express');
const router = express.Router();

const inbox = [];

// Formulario para enviar mensaje
router.get('/send', (req, res) => {
  res.render('enviarMensaje1', {
    title: 'Enviar mensaje'
  });
});

// Procesar envío
router.post('/send', (req, res) => {
  console.log('BODY RECIBIDO:', req.body);

  const username = req.body?.username;
  const text = req.body?.text;

  if (!username || !text || username.trim() === '' || text.trim() === '') {
    return res.redirect('/message1/send');
  }

  const mensaje = {
    id: Math.random().toString(36).slice(2) + Date.now().toString(36),
    username: username.trim(),
    text: text.trim(),
    timestamp: new Date().toLocaleString()
  };

  inbox.push(mensaje);

  console.log('MENSAJE GUARDADO:', mensaje);
  console.log('ESTADO ACTUAL DE INBOX:', inbox);

  res.redirect('/message1/inbox');
});

// Ver mensajes
router.get('/inbox', (req, res) => {
  res.render('chat1', {
    title: 'Bandeja de mensajes',
    mensajes: inbox
  });
});

module.exports = router;