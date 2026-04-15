const express = require('express');
const router = express.Router();
const Message2 = require('../models/message2');
const User2 = require('../models/User2');

function requireAuth(req, res, next) {
    if (!req.session.user) {
        req.session.error = 'Debes iniciar sesión para acceder a esta página';
        return res.redirect('/auth2/login');
    }
    next();
}

// Lista de usuarios con los que se puede hablar
router.get('/inbox', requireAuth, async (req, res) => {
    try {
        const usuarios = await User2.find({
            username: { $ne: req.session.user.username }
        }).sort({ username: 1 });

        res.render('app2/inbox2', {
            title: 'Bandeja de entrada',
            username: req.session.user.username,
            usuarios
        });
    } catch (error) {
        console.error(error);
        res.status(500).send('Error al cargar conversaciones');
    }
});

// Ver conversación con un usuario concreto
router.get('/chat/:username', requireAuth, async (req, res) => {
    try {
        const otroUsuario = req.params.username;

        const mensajes = await Message2.find({
            $or: [
                { from: req.session.user.username, to: otroUsuario },
                { from: otroUsuario, to: req.session.user.username }
            ]
        }).sort({ _id: 1 });

        res.render('app2/chat2', {
            title: `Chat con ${otroUsuario}`,
            username: req.session.user.username,
            otroUsuario,
            mensajes
        });
    } catch (error) {
        console.error(error);
        res.status(500).send('Error al cargar el chat');
    }
});

// Enviar mensaje dentro de la conversación
router.post('/chat/:username', requireAuth, async (req, res) => {
    try {
        const otroUsuario = req.params.username;
        const text = req.body?.text?.trim();

        if (!text) {
            return res.redirect(`/message2/chat/${otroUsuario}`);
        }

        const nuevoMensaje = new Message2({
            from: req.session.user.username,
            to: otroUsuario,
            text,
            timestamp: new Date().toLocaleString()
        });

        await nuevoMensaje.save();

        res.redirect(`/message2/chat/${otroUsuario}`);
    } catch (error) {
        console.error(error);
        res.status(500).send('Error al enviar mensaje');
    }
});

module.exports = router;