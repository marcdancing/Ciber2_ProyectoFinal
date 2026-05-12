const express = require('express');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

const router = express.Router();
const getUser3Model = require('../models/User3');

const {
  normalizeIdentity,
  hashIdentity,
  encryptIdentity,
  decryptIdentity
} = require('../utils/identityProtection');

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

    const username = normalizeIdentity(req.body.username);
    const password = req.body.password;

    if (!username || !password) {
      req.session.error = 'Debes rellenar todos los campos';
      return res.redirect('/auth3/login');
    }

    const usernameHash = hashIdentity(username);

    const user = await User3.findOne({ usernameHash });

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
      id: String(user._id),
      username
    };

    res.redirect('/auth3/mfa');
  } catch (error) {
    console.error('ERROR EN /auth3/login:', error);
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

    const decryptedUsername = decryptIdentity(user.usernameEncrypted);

    if (!decryptedUsername) {
      req.session.error = 'Error recuperando la identidad del usuario';
      return res.redirect('/auth3/login');
    }

    req.session.regenerate((err) => {
      if (err) {
        console.error(err);
        req.session.error = 'Error al iniciar sesión';
        return res.redirect('/auth3/login');
      }

      req.session.user3 = {
        id: String(user._id),
        username: decryptedUsername
      };

      req.session.pendingMfaUser = null;

      res.redirect('/message3/inbox');
    });
  } catch (error) {
    console.error('ERROR EN /auth3/mfa:', error);
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

    const username = normalizeIdentity(req.body.username);
    const email = normalizeIdentity(req.body.email);
    const password = req.body.password;
    const passwordConfirm = req.body.passwordConfirm;
    const publicKey = req.body.publicKey;

   if (!passwordConfirm) {
    req.session.error = 'Debes repetir la contraseña';
    return res.redirect('/auth3/register');
  }

  if (password !== passwordConfirm) {
    req.session.error = 'Las contraseñas no coinciden';
    return res.redirect('/auth3/register');
  }

    const passwordRegex =
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z\d]).{10,}$/;

    if (!passwordRegex.test(password)) {
      req.session.error =
        'La contraseña debe tener al menos 10 caracteres e incluir mayúsculas, minúsculas, números y caracteres especiales.';
      return res.redirect('/auth3/register');
    }

    const commonPasswords = [
      'password',
      'password123',
      '123456',
      '123456789',
      'qwerty',
      'admin',
      'admin123',
      'hola123',
      'securegov123',
      'contraseña',
      'contraseña123'
    ];

    if (commonPasswords.includes(password.toLowerCase())) {
      req.session.error = 'La contraseña es demasiado común. Utiliza una contraseña más segura.';
      return res.redirect('/auth3/register');
    }

    if (!publicKey) {
      req.session.error = 'Error generando el certificado. Inténtalo de nuevo.';
      return res.redirect('/auth3/register');
    }

    const usernameHash = hashIdentity(username);
    const emailHash = hashIdentity(email);

    const existingUser = await User3.findOne({
      $or: [
        { usernameHash },
        { emailHash }
      ]
    });

    if (existingUser) {
      req.session.error = 'El usuario o email ya existe';
      return res.redirect('/auth3/register');
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const mfaSecret = speakeasy.generateSecret({
      name: `SecureGov (${username})`
    });

    const qrCodeDataUrl = await QRCode.toDataURL(mfaSecret.otpauth_url);

    const newUser = new User3({
      usernameHash,
      emailHash,
      usernameEncrypted: encryptIdentity(username),
      emailEncrypted: encryptIdentity(email),
      password: hashedPassword,
      publicKey,
      mfaSecret: mfaSecret.base32,
      mfaEnabled: true,
      certificateVersion: 1,
      certificateRevokedAt: null,
      certificateUpdatedAt: new Date()
    });

    await newUser.save();

    req.session.mfaSetup = {
      username,
      qrCodeDataUrl
    };

    res.redirect('/auth3/setup-mfa');
  } catch (error) {
    console.error('ERROR EN /auth3/register:', error);
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

// Guardar clave pública del usuario actual
router.post('/public-key', requireAuth3, async (req, res) => {
  try {
    const User3 = getUser3Model();
    const publicKey = req.body?.publicKey;

    if (!publicKey) {
      return res.status(400).json({
        error: 'Falta la clave pública'
      });
    }

    await User3.updateOne(
      { _id: req.session.user3.id },
      {
        $set: {
          publicKey,
          certificateUpdatedAt: new Date()
        }
      }
    );

    res.json({ ok: true });
  } catch (error) {
    console.error('ERROR EN /auth3/public-key:', error);
    res.status(500).json({
      error: 'Error guardando la clave pública'
    });
  }
});

// Obtener clave pública de otro usuario por ID
router.get('/public-key/user/:userId', requireAuth3, async (req, res) => {
  try {
    const User3 = getUser3Model();

    const user = await User3.findById(req.params.userId);

    if (!user || !user.publicKey) {
      return res.status(404).json({
        error: 'Clave pública no encontrada'
      });
    }

    res.json({
      userId: String(user._id),
      publicKey: user.publicKey,
      certificateVersion: user.certificateVersion || 1
    });
  } catch (error) {
    console.error('ERROR EN /auth3/public-key/user/:userId:', error);
    res.status(500).json({
      error: 'Error obteniendo la clave pública'
    });
  }
});

// Mostrar pantalla de revocación de certificado
router.get('/revoke-certificate', requireAuth3, async (req, res) => {
  try {
    const error = req.session.error || null;
    req.session.error = null;

    res.render('app3/revokeCertificate3', {
      title: 'Revocar certificado',
      username: req.session.user3.username,
      error,
      query: req.query
    });
  } catch (error) {
    console.error('ERROR EN GET /auth3/revoke-certificate:', error);
    req.session.error = 'Error cargando la pantalla de revocación';
    res.redirect('/message3/inbox');
  }
});

// Verificar MFA antes de permitir revocar el certificado
router.post('/revoke-certificate/verify-mfa', requireAuth3, async (req, res) => {
  try {
    const User3 = getUser3Model();

    const token = req.body.token?.trim();
    const confirmation = req.body.confirmation;

    if (confirmation !== 'on') {
      req.session.error = 'Debes confirmar que entiendes las consecuencias de la revocación.';
      return res.redirect('/auth3/revoke-certificate');
    }

    if (!token) {
      req.session.error = 'Introduce el código MFA para continuar.';
      return res.redirect('/auth3/revoke-certificate');
    }

    const user = await User3.findById(req.session.user3.id);

    if (!user || !user.mfaSecret) {
      req.session.error = 'MFA no configurado.';
      return res.redirect('/auth3/revoke-certificate');
    }

    const verified = speakeasy.totp.verify({
      secret: user.mfaSecret,
      encoding: 'base32',
      token,
      window: 1
    });

    if (!verified) {
      req.session.error = 'Código MFA incorrecto.';
      return res.redirect('/auth3/revoke-certificate');
    }

    req.session.certificateRevocationApproved = {
      userId: String(user._id),
      approvedAt: Date.now()
    };

    res.redirect('/auth3/revoke-certificate?approved=1');
  } catch (error) {
    console.error('ERROR EN POST /auth3/revoke-certificate/verify-mfa:', error);
    req.session.error = 'Error verificando MFA.';
    res.redirect('/auth3/revoke-certificate');
  }
});

// Completar revocación: guardar nueva clave pública
router.post('/revoke-certificate/complete', requireAuth3, async (req, res) => {
  try {
    const User3 = getUser3Model();

    const approval = req.session.certificateRevocationApproved;

    if (!approval || approval.userId !== String(req.session.user3.id)) {
      return res.status(403).json({
        ok: false,
        error: 'Revocación no autorizada. Debes verificar MFA primero.'
      });
    }

    const approvalExpired =
      Date.now() - approval.approvedAt > 5 * 60 * 1000;

    if (approvalExpired) {
      req.session.certificateRevocationApproved = null;

      return res.status(403).json({
        ok: false,
        error: 'La autorización MFA ha expirado. Vuelve a intentarlo.'
      });
    }

    const publicKey = req.body.publicKey;

    if (!publicKey) {
      return res.status(400).json({
        ok: false,
        error: 'Falta la nueva clave pública.'
      });
    }

    const user = await User3.findById(req.session.user3.id);

    if (!user) {
      return res.status(404).json({
        ok: false,
        error: 'Usuario no encontrado.'
      });
    }

    user.publicKey = publicKey;
    user.certificateVersion = (user.certificateVersion || 1) + 1;
    user.certificateRevokedAt = new Date();
    user.certificateUpdatedAt = new Date();

    await user.save();

    req.session.certificateRevocationApproved = null;
    req.session.captchaSolvedAt = null;
    req.session.messageTimestamps = [];

    res.json({
      ok: true,
      certificateVersion: user.certificateVersion
    });
  } catch (error) {
    console.error('ERROR EN POST /auth3/revoke-certificate/complete:', error);

    res.status(500).json({
      ok: false,
      error: 'Error completando la revocación del certificado.'
    });
  }
});

// Mostrar formulario de cambio de contraseña
// Mostrar formulario de recuperación de contraseña
router.get('/forgot-password', (req, res) => {
  const error = req.session.error || null;
  const success = req.session.success || null;

  req.session.error = null;
  req.session.success = null;

  res.render('app3/forgotPassword3', {
    title: 'Recuperar contraseña',
    error,
    success
  });
});

// Procesar recuperación de contraseña
router.post('/forgot-password', async (req, res) => {
  try {
    const User3 = getUser3Model();

    const identifier = normalizeIdentity(req.body.identifier);
    const newPassword = req.body.newPassword;
    const newPasswordConfirm = req.body.newPasswordConfirm;
    const token = req.body.token?.trim();

    if (!identifier || !newPassword || !newPasswordConfirm || !token) {
      req.session.error = 'Debes rellenar todos los campos';
      return res.redirect('/auth3/forgot-password');
    }

    if (newPassword !== newPasswordConfirm) {
      req.session.error = 'Las nuevas contraseñas no coinciden';
      return res.redirect('/auth3/forgot-password');
    }

    const passwordRegex =
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z\d]).{10,}$/;

    if (!passwordRegex.test(newPassword)) {
      req.session.error =
        'La nueva contraseña debe tener al menos 10 caracteres e incluir mayúsculas, minúsculas, números y caracteres especiales.';
      return res.redirect('/auth3/forgot-password');
    }

    const commonPasswords = [
      'password',
      'password123',
      '123456',
      '123456789',
      'qwerty',
      'admin',
      'admin123',
      'hola123',
      'securegov123',
      'contraseña',
      'contraseña123'
    ];

    if (commonPasswords.includes(newPassword.toLowerCase())) {
      req.session.error = 'La nueva contraseña es demasiado común. Utiliza una contraseña más segura.';
      return res.redirect('/auth3/forgot-password');
    }

    const identifierHash = hashIdentity(identifier);

    const user = await User3.findOne({
      $or: [
        { usernameHash: identifierHash },
        { emailHash: identifierHash }
      ]
    });

    // Mensaje genérico para no revelar si existe o no el usuario
    if (!user) {
      req.session.error = 'No se pudo validar la recuperación de contraseña';
      return res.redirect('/auth3/forgot-password');
    }

    if (!user.mfaSecret) {
      req.session.error = 'La cuenta no tiene MFA configurado';
      return res.redirect('/auth3/forgot-password');
    }

    const verified = speakeasy.totp.verify({
      secret: user.mfaSecret,
      encoding: 'base32',
      token,
      window: 1
    });

    if (!verified) {
      req.session.error = 'No se pudo validar la recuperación de contraseña';
      return res.redirect('/auth3/forgot-password');
    }

    const hashedPassword = await bcrypt.hash(newPassword, 12);

    user.password = hashedPassword;
    await user.save();

    req.session.success = 'Contraseña recuperada correctamente. Ya puedes iniciar sesión.';

    res.redirect('/auth3/forgot-password');
  } catch (error) {
    console.error('ERROR EN POST /auth3/forgot-password:', error);
    req.session.error = 'Error recuperando la contraseña';
    res.redirect('/auth3/forgot-password');
  }
});

// Procesar cambio de contraseña
router.post('/change-password', async (req, res) => {
  try {
    const User3 = getUser3Model();

    const currentPassword = req.body.currentPassword;
    const newPassword = req.body.newPassword;
    const newPasswordConfirm = req.body.newPasswordConfirm;
    const token = req.body.token?.trim();

    if (!currentPassword || !newPassword || !newPasswordConfirm || !token) {
      req.session.error = 'Debes rellenar todos los campos';
      return res.redirect('/auth3/change-password');
    }

    if (newPassword !== newPasswordConfirm) {
      req.session.error = 'Las nuevas contraseñas no coinciden';
      return res.redirect('/auth3/change-password');
    }

    if (currentPassword === newPassword) {
      req.session.error = 'La nueva contraseña no puede ser igual a la contraseña actual';
      return res.redirect('/auth3/change-password');
    }

    const passwordRegex =
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z\d]).{10,}$/;

    if (!passwordRegex.test(newPassword)) {
      req.session.error =
        'La nueva contraseña debe tener al menos 10 caracteres e incluir mayúsculas, minúsculas, números y caracteres especiales.';
      return res.redirect('/auth3/change-password');
    }

    const commonPasswords = [
      'password',
      'password123',
      '123456',
      '123456789',
      'qwerty',
      'admin',
      'admin123',
      'hola123',
      'securegov123',
      'contraseña',
      'contraseña123'
    ];

    if (commonPasswords.includes(newPassword.toLowerCase())) {
      req.session.error = 'La nueva contraseña es demasiado común. Utiliza una contraseña más segura.';
      return res.redirect('/auth3/change-password');
    }

    const user = await User3.findById(req.session.user3.id);

    if (!user) {
      req.session.error = 'Usuario no encontrado';
      return res.redirect('/auth3/login');
    }

    const currentPasswordOk = await bcrypt.compare(currentPassword, user.password);

    if (!currentPasswordOk) {
      req.session.error = 'La contraseña actual no es correcta';
      return res.redirect('/auth3/change-password');
    }

    if (!user.mfaSecret) {
      req.session.error = 'MFA no configurado para este usuario';
      return res.redirect('/auth3/change-password');
    }

    const verified = speakeasy.totp.verify({
      secret: user.mfaSecret,
      encoding: 'base32',
      token,
      window: 1
    });

    if (!verified) {
      req.session.error = 'Código MFA incorrecto';
      return res.redirect('/auth3/change-password');
    }

    const hashedPassword = await bcrypt.hash(newPassword, 12);

    user.password = hashedPassword;
    await user.save();

    req.session.success = 'Contraseña actualizada correctamente';

    res.redirect('/auth3/change-password');
  } catch (error) {
    console.error('ERROR EN POST /auth3/change-password:', error);
    req.session.error = 'Error cambiando la contraseña';
    res.redirect('/auth3/change-password');
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