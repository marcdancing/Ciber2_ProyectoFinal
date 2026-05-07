const express = require('express');
const svgCaptcha = require('svg-captcha');
const crypto = require('crypto');

const router = express.Router();

const getMessage3Model = require('../models/message3');
const getUser3Model = require('../models/User3');

const MESSAGE_LIMIT = 5;
const MESSAGE_WINDOW_MS = 30 * 1000;

const CAPTCHA_VALID_MS = 2 * 60 * 1000;
const CAPTCHA_EXPIRATION_MS = 5 * 60 * 1000;
const MAX_CAPTCHA_ATTEMPTS = 5;

function requireAuth3(req, res, next) {
  if (!req.session.user3) {
    req.session.error = 'Debes iniciar sesión para acceder a esta página';
    return res.redirect('/auth3/login');
  }

  next();
}

function checkMessageRateLimit(req) {
  const now = Date.now();

  if (!req.session.messageTimestamps) {
    req.session.messageTimestamps = [];
  }

  req.session.messageTimestamps = req.session.messageTimestamps.filter(
    timestamp => now - timestamp < MESSAGE_WINDOW_MS
  );

  if (req.session.messageTimestamps.length >= MESSAGE_LIMIT) {
    return false;
  }

  req.session.messageTimestamps.push(now);
  return true;
}

function hashCaptchaAnswer(answer) {
  return crypto
    .createHash('sha256')
    .update(String(answer).toLowerCase().trim())
    .digest('hex');
}

function generateSecureCaptcha() {
  return svgCaptcha.create({
    size: 6,
    noise: 5,
    color: true,
    background: '#f8fafc',
    width: 220,
    height: 80,
    fontSize: 48,
    charPreset: 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
  });
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

// // Ver chat con un usuario concreto

// Ver chat con un usuario concreto
router.get('/chat/:username', requireAuth3, async (req, res) => {
  try {
    const Message3 = getMessage3Model();
    const User3 = getUser3Model();

    const otroUsuario = req.params.username?.trim().toLowerCase();

    if (!otroUsuario) {
      req.session.error = 'Usuario no válido';
      return res.redirect('/message3/inbox');
    }

    const existeUsuario = await User3.findOne({ username: otroUsuario });

    if (!existeUsuario) {
      req.session.error = 'El usuario seleccionado no existe';
      return res.redirect('/message3/inbox');
    }

    const currentUser = await User3.findById(req.session.user3.id);

    if (!currentUser) {
      req.session.error = 'No se ha podido cargar el usuario actual';
      return res.redirect('/auth3/login');
    }

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
      error,
      certificateVersion: currentUser.certificateVersion || 1
    });
  } catch (error) {
    console.error('ERROR EN /message3/chat/:username:', error);
    res.status(500).send('Error al cargar el chat');
  }
});
// router.get('/chat/:username', requireAuth3, async (req, res) => {
//   try {
//     const Message3 = getMessage3Model();
//     const User3 = getUser3Model();

//     const otroUsuario = req.params.username?.trim().toLowerCase();

//     const existeUsuario = await User3.findOne({ username: otroUsuario });

//     if (!existeUsuario) {
//       req.session.error = 'El usuario seleccionado no existe';
//       return res.redirect('/message3/inbox');
//     }

//     const mensajes = await Message3.find({
//       $or: [
//         { from: req.session.user3.username, to: otroUsuario },
//         { from: otroUsuario, to: req.session.user3.username }
//       ]
//     }).sort({ _id: 1 });

//     const error = req.session.error || null;
//     req.session.error = null;

//     res.render('app3/chat3', {
//       title: `Chat con ${otroUsuario}`,
//       username: req.session.user3.username,
//       otroUsuario,
//       mensajes,
//       error,
//       certificateVersion: currentUser?.certificateVersion || 1,
//     });
//   } catch (error) {
//     console.error('ERROR EN /message3/chat/:username:', error);
//     res.status(500).send('Error al cargar el chat');
//   }
// });

// Guardar mensaje ya cifrado desde cliente
router.post('/chat/:username', requireAuth3, async (req, res) => {
  try {
    const Message3 = getMessage3Model();
    const User3 = getUser3Model();

    const otroUsuario = req.params.username?.trim().toLowerCase();

    const existeUsuario = await User3.findOne({ username: otroUsuario });
    

    if (!existeUsuario) {
      return res.status(404).json({
        error: 'El usuario destinatario no existe'
      });
    }

    const captchaRecentlySolved =
      req.session.captchaSolvedAt &&
      Date.now() - req.session.captchaSolvedAt < CAPTCHA_VALID_MS;

    if (!captchaRecentlySolved) {
      const allowed = checkMessageRateLimit(req);

      if (!allowed) {
        return res.status(429).json({
          captchaRequired: true,
          error: 'Demasiados mensajes enviados en poco tiempo. Verificación humana requerida.'
        });
      }
    }

    const {
      ciphertext,
      iv,
      encryptedKeyForRecipient,
      encryptedKeyForSender
    } = req.body;

    if (!ciphertext || !iv || !encryptedKeyForRecipient || !encryptedKeyForSender) {
      return res.status(400).json({
        error: 'Faltan datos cifrados del mensaje'
      });
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

    await nuevoMensaje.save();

    res.json({ ok: true });
  } catch (error) {
    console.error('ERROR EN POST /message3/chat/:username:', error);
    res.status(500).json({ error: 'Error al enviar mensaje' });
  }
});

// Generar CAPTCHA gráfico
router.get('/captcha', requireAuth3, (req, res) => {
  const captcha = generateSecureCaptcha();

  req.session.captchaHash = hashCaptchaAnswer(captcha.text);
  req.session.captchaCreatedAt = Date.now();
  req.session.captchaAttempts = 0;

  res.json({
    svg: captcha.data
  });
});

// Verificar CAPTCHA gráfico
router.post('/captcha', requireAuth3, (req, res) => {
  const answer = req.body.answer?.trim();

  if (!req.session.captchaHash || !req.session.captchaCreatedAt) {
    return res.status(400).json({
      ok: false,
      error: 'CAPTCHA no inicializado'
    });
  }

  const expired =
    Date.now() - req.session.captchaCreatedAt > CAPTCHA_EXPIRATION_MS;

  if (expired) {
    req.session.captchaHash = null;
    req.session.captchaCreatedAt = null;
    req.session.captchaAttempts = 0;

    return res.status(400).json({
      ok: false,
      error: 'CAPTCHA expirado'
    });
  }

  req.session.captchaAttempts = (req.session.captchaAttempts || 0) + 1;

  if (req.session.captchaAttempts > MAX_CAPTCHA_ATTEMPTS) {
    req.session.captchaHash = null;
    req.session.captchaCreatedAt = null;
    req.session.captchaAttempts = 0;

    return res.status(429).json({
      ok: false,
      error: 'Demasiados intentos de CAPTCHA'
    });
  }

  if (!answer || hashCaptchaAnswer(answer) !== req.session.captchaHash) {
    return res.status(400).json({
      ok: false,
      error: 'CAPTCHA incorrecto'
    });
  }

  req.session.captchaSolvedAt = Date.now();
  req.session.captchaHash = null;
  req.session.captchaCreatedAt = null;
  req.session.captchaAttempts = 0;
  req.session.messageTimestamps = [];

  res.json({ ok: true });
});

module.exports = router;