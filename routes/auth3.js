const express = require('express');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

const router = express.Router();
const getUser3Model = require('../models/User3');

function requireAuth3(req, res, next) {
  if (!req.session.user3) {
    req.session.error = 'Debes iniciar sesión para acceder a esta página';
    return res.redirect('/auth3/login');
  }
  next();
}

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Demasiados intentos de inicio de sesión. Inténtalo más tarde.'
});

// Mostrar login
router.get('/login', (req, res) => {
  const error = req.session.error || null;
  req.session.error = null;

  res.render('app3/login3', {
    title: 'Login App 3',
    error
  });
});

// Procesar login: usuario + contraseña
router.post('/login', loginLimiter, async (req, res) => {
  try {
    const User3 = getUser3Model();

    const username = req.body.username?.trim().toLowerCase();
    const password = req.body.password?.trim();

    if (!username || !password) {
      req.session.error = 'Debes rellenar todos los campos';
      return res.redirect('/auth3/login');
    }

    const user = await User3.findOne({ username });

    if (!user) {
      req.session.error = 'Usuario o contraseña incorrectos';
      return res.redirect('/auth3/login');
    }

    const passwordOk = await bcrypt.compare(password, user.password);

    if (!passwordOk) {
      req.session.error = 'Usuario o contraseña incorrectos';
      return res.redirect('/auth3/login');
    }

    req.session.pendingMfaUser = {
      id: user._id,
      username: user.username
    };

    res.redirect('/auth3/mfa');
  } catch (error) {
    console.error(error);
    req.session.error = 'Error interno al iniciar sesión';
    res.redirect('/auth3/login');
  }
});

// Mostrar MFA
router.get('/mfa', (req, res) => {
  if (!req.session.pendingMfaUser) {
    return res.redirect('/auth3/login');
  }

  const error = req.session.error || null;
  req.session.error = null;

  res.render('app3/mfa3', {
    title: 'Verificación MFA',
    username: req.session.pendingMfaUser.username,
    error
  });
});

// Procesar MFA
router.post('/mfa', async (req, res) => {
  try {
    const User3 = getUser3Model();

    if (!req.session.pendingMfaUser) {
      return res.redirect('/auth3/login');
    }

    const token = req.body.token?.trim();

    if (!token) {
      req.session.error = 'Introduce el código MFA';
      return res.redirect('/auth3/mfa');
    }

    const user = await User3.findById(req.session.pendingMfaUser.id);

    if (!user || !user.mfaSecret) {
      req.session.error = 'MFA no configurado';
      return res.redirect('/auth3/login');
    }

    const verified = speakeasy.totp.verify({
      secret: user.mfaSecret,
      encoding: 'base32',
      token,
      window: 1
    });

    if (!verified) {
      req.session.error = 'Código MFA incorrecto';
      return res.redirect('/auth3/mfa');
    }

    req.session.regenerate((err) => {
      if (err) {
        console.error(err);
        req.session.error = 'Error al iniciar sesión';
        return res.redirect('/auth3/login');
      }

      req.session.user3 = {
        id: user._id,
        username: user.username
      };

      req.session.pendingMfaUser = null;

      res.redirect('/message3/inbox');
    });
  } catch (error) {
    console.error(error);
    req.session.error = 'Error verificando MFA';
    res.redirect('/auth3/mfa');
  }
});

// Mostrar registro
router.get('/register', (req, res) => {
  const error = req.session.error || null;
  req.session.error = null;

  res.render('app3/register3', {
    title: 'Registro App 3',
    error
  });
});

// Procesar registro
router.post('/register', async (req, res) => {
  try {
    const User3 = getUser3Model();

    const username = req.body.username?.trim().toLowerCase();
    const email = req.body.email?.trim().toLowerCase();
    const password = req.body.password?.trim();
    const publicKey = req.body.publicKey;

    if (!username || !email || !password) {
      req.session.error = 'Debes rellenar todos los campos';
      return res.redirect('/auth3/register');
    }

    if (password.length < 8) {
      req.session.error = 'La contraseña debe tener al menos 8 caracteres';
      return res.redirect('/auth3/register');
    }

    if (!publicKey) {
      req.session.error = 'Error generando el certificado. Inténtalo de nuevo.';
      return res.redirect('/auth3/register');
    }

    const existingUser = await User3.findOne({ username });

    if (existingUser) {
      req.session.error = 'El usuario ya existe';
      return res.redirect('/auth3/register');
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const mfaSecret = speakeasy.generateSecret({
      name: `SecureGov (${username})`
    });

    const qrCodeDataUrl = await QRCode.toDataURL(mfaSecret.otpauth_url);

    const newUser = new User3({
      username,
      email,
      password: hashedPassword,
      publicKey,
      mfaSecret: mfaSecret.base32,
      mfaEnabled: true
    });

    await newUser.save();

    req.session.mfaSetup = {
      username,
      qrCodeDataUrl
    };

    res.redirect('/auth3/setup-mfa');
  } catch (error) {
    console.error(error);
    req.session.error = 'Error al registrar el usuario';
    res.redirect('/auth3/register');
  }
});

// Mostrar QR MFA tras registro
router.get('/setup-mfa', (req, res) => {
  if (!req.session.mfaSetup) {
    return res.redirect('/auth3/login');
  }

  res.render('app3/setupMfa3', {
    title: 'Configurar MFA',
    username: req.session.mfaSetup.username,
    qrCodeDataUrl: req.session.mfaSetup.qrCodeDataUrl
  });
});

// Guardar clave pública
router.post('/public-key', requireAuth3, async (req, res) => {
  try {
    const User3 = getUser3Model();
    const publicKey = req.body?.publicKey;

    if (!publicKey) {
      return res.status(400).json({ error: 'Falta la clave pública' });
    }

    await User3.updateOne(
      { _id: req.session.user3.id },
      { $set: { publicKey } }
    );

    res.json({ ok: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error guardando la clave pública' });
  }
});

// Obtener clave pública de otro usuario
router.get('/public-key/:username', requireAuth3, async (req, res) => {
  try {
    const User3 = getUser3Model();
    const username = req.params.username?.trim().toLowerCase();

    const user = await User3.findOne({ username });

    if (!user || !user.publicKey) {
      return res.status(404).json({ error: 'Clave pública no encontrada' });
    }

    res.json({
      username: user.username,
      publicKey: user.publicKey
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error obteniendo la clave pública' });
  }
});

// Logout
router.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.redirect('/auth3/login');
  });
});

module.exports = router;