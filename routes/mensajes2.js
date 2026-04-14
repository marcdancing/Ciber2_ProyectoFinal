const express = require('express');
const router = express.Router();
const Message2 = require('../models/message2');
console.log('MESSAGE2 IMPORTADO: ', Message2);  
const User2 = require('../models/User2');

function requireAuth(req, res, next) {
    if (!req.session.user) {
        req.session.error = 'Debes iniciar sesión para acceder a esta página';
        return res.redirect('/auth2/login');
    }
    next();
}

// Ver mensajes recibidos
router.get('/inbox', requireAuth, async (req, res) => {
    try {
        const mensajes = await Message2.find({
          $or: [
            { to: req.session.user.username },
            { from: req.session.user.username }
              ]
        }).sort({ _id: 1 });

        res.render('app2/chat2', {
            title: 'Bandeja de entrada',
            username: req.session.user.username,
            mensajes
        });
    } catch (error) {
        console.error(error);
        res.status(500).send('Error al cargar mensajes');
    }
});

// Mostrar formulario para enviar mensaje
router.get('/send', requireAuth, async (req, res) => {
    try {
        const usuarios = await User2.find({
            username: { $ne: req.session.user.username }
        });

        res.render('app2/enviarMensaje2', {
            title: 'Enviar mensaje',
            username: req.session.user.username,
            usuarios
        });
    } catch (error) {
        console.error(error);
        res.status(500).send('Error al cargar usuarios');
    }
});

// Enviar mensaje
router.post('/send', requireAuth, async (req, res) => {
    try {
        const to = req.body?.to?.trim();
        const text = req.body?.text?.trim();

        if (!to || !text) {
            return res.redirect('/message2/send');
        }

        const nuevoMensaje = new Message2({
            from: req.session.user.username,
            to,
            text,
            timestamp: new Date().toLocaleString()
        });

        await nuevoMensaje.save();

        res.redirect('/message2/inbox');
    } catch (error) {
        console.error(error);
        res.status(500).send('Error al enviar mensaje');
    }
});

module.exports = router;