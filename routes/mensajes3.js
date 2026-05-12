const express = require('express');
const svgCaptcha = require('svg-captcha');
const crypto = require('crypto');
const mongoose = require('mongoose');

const router = express.Router();

const getMessage3Model = require('../models/message3');
const getUser3Model = require('../models/User3');
const {
  decryptIdentity,
  hashInternalId
} = require('../utils/identityProtection');

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

function isValidObjectId(id) {
  return mongoose.Types.ObjectId.isValid(id);
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

    const usuariosRaw = await User3.find({
      _id: { $ne: req.session.user3.id }
    }).sort({ _id: 1 });

    const usuarios = usuariosRaw
      .map(user => {
        const username = decryptIdentity(user.usernameEncrypted);

        if (!username) {
          return null;
        }

        return {
          id: String(user._id),
          username,
          certificateVersion: user.certificateVersion || 1
        };
      })
      .filter(Boolean);

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

// Ver chat con un usuario concreto// Ver chat con un usuario concreto
router.get('/chat/:userId', requireAuth3, async (req, res) => {
  try {
    const Message3 = getMessage3Model();
    const User3 = getUser3Model();

    const otroUsuarioId = req.params.userId;

    if (!otroUsuarioId) {
      req.session.error = 'Identificador de usuario no válido';
      return res.redirect('/message3/inbox');
    }

    if (String(otroUsuarioId) === String(req.session.user3.id)) {
      req.session.error = 'No puedes abrir un chat contigo mismo';
      return res.redirect('/message3/inbox');
    }

    const currentUser = await User3.findById(req.session.user3.id);

    if (!currentUser) {
      req.session.error = 'No se ha podido cargar el usuario actual';
      return res.redirect('/auth3/login');
    }

    const existeUsuario = await User3.findById(otroUsuarioId);

    if (!existeUsuario) {
      req.session.error = 'El usuario seleccionado no existe';
      return res.redirect('/message3/inbox');
    }

    const otroUsuarioNombre = decryptIdentity(existeUsuario.usernameEncrypted);

    if (!otroUsuarioNombre) {
      req.session.error = 'No se pudo recuperar la identidad del usuario seleccionado';
      return res.redirect('/message3/inbox');
    }

    const currentUserHash = hashInternalId(currentUser._id);
    const otherUserHash = hashInternalId(existeUsuario._id);

    const mensajesRaw = await Message3.find({
      $or: [
        { fromUserHash: currentUserHash, toUserHash: otherUserHash },
        { fromUserHash: otherUserHash, toUserHash: currentUserHash }
      ]
    }).sort({ _id: 1 });

    const mensajes = mensajesRaw.map(msg => ({
      id: String(msg._id),
      fromUserHash: msg.fromUserHash,
      toUserHash: msg.toUserHash,
      ciphertext: msg.ciphertext,
      iv: msg.iv,
      encryptedKeyForRecipient: msg.encryptedKeyForRecipient,
      encryptedKeyForSender: msg.encryptedKeyForSender,
      timestamp: msg.timestamp
    }));

    const error = req.session.error || null;
    req.session.error = null;

    res.render('app3/chat3', {
      title: 'Chat seguro',
      username: req.session.user3.username,
      currentUserId: String(currentUser._id),
      otroUsuarioId: String(existeUsuario._id),
      currentUserHash,
      otherUserHash,
      otroUsuario: otroUsuarioNombre,
      mensajes,
      error,
      certificateVersion: currentUser.certificateVersion || 1
    });
  } catch (error) {
    console.error('ERROR EN /message3/chat/:userId:', error);
    res.status(500).send('Error al cargar el chat');
  }
});

// Guardar mensaje ya cifrado desde cliente
router.post('/chat/:userId', requireAuth3, async (req, res) => {
  try {
    const Message3 = getMessage3Model();
    const User3 = getUser3Model();

    const otroUsuarioId = req.params.userId;

    if (!isValidObjectId(otroUsuarioId)) {
      return res.status(400).json({
        error: 'Identificador de usuario no válido'
      });
    }

    if (String(otroUsuarioId) === String(req.session.user3.id)) {
      return res.status(400).json({
        error: 'No puedes enviarte mensajes a ti mismo'
      });
    }

    const currentUser = await User3.findById(req.session.user3.id);
    const destinatario = await User3.findById(otroUsuarioId);

    if (!currentUser) {
      return res.status(401).json({
        error: 'Usuario actual no válido'
      });
    }

    if (!destinatario) {
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
      fromUserHash: hashInternalId(currentUser._id),
      toUserHash: hashInternalId(destinatario._id),
      ciphertext,
      iv,
      encryptedKeyForRecipient,
      encryptedKeyForSender,
      timestamp: new Date().toLocaleString()
    });

    await nuevoMensaje.save();

    res.json({ ok: true });
  } catch (error) {
    console.error('ERROR EN POST /message3/chat/:userId:', error);
    res.status(500).json({
      error: 'Error al enviar mensaje'
    });
  }
});

// Obtener mensajes cifrados del chat sin recargar la página
router.get('/chat/:userId/messages', requireAuth3, async (req, res) => {
  try {
    const Message3 = getMessage3Model();
    const User3 = getUser3Model();

    const otroUsuarioId = req.params.userId;

    if (!otroUsuarioId) {
      return res.status(400).json({
        error: 'Identificador de usuario no válido'
      });
    }

    if (String(otroUsuarioId) === String(req.session.user3.id)) {
      return res.status(400).json({
        error: 'No puedes abrir un chat contigo mismo'
      });
    }

    const currentUser = await User3.findById(req.session.user3.id);
    const existeUsuario = await User3.findById(otroUsuarioId);

    if (!currentUser || !existeUsuario) {
      return res.status(404).json({
        error: 'Usuario no encontrado'
      });
    }

    const currentUserHash = hashInternalId(currentUser._id);
    const otherUserHash = hashInternalId(existeUsuario._id);

    const mensajesRaw = await Message3.find({
      $or: [
        { fromUserHash: currentUserHash, toUserHash: otherUserHash },
        { fromUserHash: otherUserHash, toUserHash: currentUserHash }
      ]
    }).sort({ _id: 1 });

    const mensajes = mensajesRaw.map(msg => ({
      id: String(msg._id),
      fromUserHash: msg.fromUserHash,
      toUserHash: msg.toUserHash,
      ciphertext: msg.ciphertext,
      iv: msg.iv,
      encryptedKeyForRecipient: msg.encryptedKeyForRecipient,
      encryptedKeyForSender: msg.encryptedKeyForSender,
      timestamp: msg.timestamp
    }));

    res.json({
      ok: true,
      mensajes
    });
  } catch (error) {
    console.error('ERROR EN GET /message3/chat/:userId/messages:', error);
    res.status(500).json({
      error: 'Error obteniendo mensajes'
    });
  }
});


// Generar CAPTCHA gráfico
router.get('/captcha', requireAuth3, (req, res) => {
  try {
    const captcha = generateSecureCaptcha();

    req.session.captchaHash = hashCaptchaAnswer(captcha.text);
    req.session.captchaCreatedAt = Date.now();
    req.session.captchaAttempts = 0;

    res.json({
      svg: captcha.data
    });
  } catch (error) {
    console.error('ERROR generando CAPTCHA:', error);
    res.status(500).json({
      error: 'Error generando CAPTCHA'
    });
  }
});

// Verificar CAPTCHA gráfico
router.post('/captcha', requireAuth3, (req, res) => {
  try {
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
  } catch (error) {
    console.error('ERROR verificando CAPTCHA:', error);
    res.status(500).json({
      ok: false,
      error: 'Error verificando CAPTCHA'
    });
  }
});

module.exports = router;