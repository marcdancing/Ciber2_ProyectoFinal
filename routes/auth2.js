const express = require('express');
const router = express.Router();
const User2 = require('../models/User2');

// Mostrar formulario de login
router.get('/login', (req, res) => {
    const error = req.session.error || null;
    req.session.error = null;

    res.render('app2/login2', {
        title: 'Login',
        error
    });
});
// Proceso de login
router.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        console.log('Login: ', { username, password });
        const user = await User2.findOne({ username, password });
        console.log('Usuario encontrado: ', user);

        if (!user) {
            return res.send('Usuario o contraseña incorrectos');
        }

        req.session.user = {
            id: user._id,
            username: user.username
        };

        res.redirect('/message2/inbox');
    } catch (error) {
        console.error(error);
        res.status(500).send('Error en el servidor');
    }
});

// Mostrar formulario de registro
router.get('/register', (req, res) => {
    res.render('app2/register2', {
        title: 'Registro'
    });
});

// Proceso de registro de usuario nuevo
router.post('/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        const existingUser = await User2.findOne({ username });

        if (existingUser) {
            return res.send('El usuario ya existe');
        }

        const newUser = new User2({
            username,
            email,
            password
        });

        await newUser.save();
        res.redirect('/auth2/login');
    } catch (error) {
        console.error(error);
        res.status(500).send('Error en el registro');
    }
});

module.exports = router;