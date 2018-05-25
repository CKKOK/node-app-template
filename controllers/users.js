const express = require('express');
const router = express.Router();
const User = require('../models/user');
const asyncf = require('../async');

router.get('/', (req, res) => {
    res.render('users', {title: 'User registration'});
});

router.post('/', async (req, res) => {
    let [err, result] = await asyncf(User.create({
        name: req.body.name,
        email: req.body.email,
        password: req.body.password
    }));
    if (err) {
        res.send('Error creating user');
    } else {
        res.redirect('/');
    };
});

router.get('/login', (req, res) => {
    res.render('login', {title: 'User login', csrfToken: req.csrfToken()});
});

router.post('/login', async (req, res) => {
    let [err, result] = await asyncf(User.authenticate(req.body.email, req.body.password));
    if (err) {
        res.send('Error finding user');
    } else {
        if (result !== false) {
            req.session.user = result;
            res.redirect('/');
        } else {
            res.send('Incorrect password');
        }
    }
});

router.get('/logout', (req, res) => {
    delete req.session.user;
    delete req.session.authenticated;
    res.clearCookie('user_sid');
    res.redirect('/');
})

module.exports = router;
