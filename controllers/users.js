const config = require('../config');
const express = require('express');
const router = express.Router();
const User = require('../models/user');
const passport = User.passport;
const asyncf = require('../async');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const multer = require('multer');
const upload = multer();

function requireLogin(req, res, next) {
    // Express Session Authentication
    // ==============================
    // if (req.session.user) {

    // JWT Authentication with Express Session
    // =======================================
    // if (req.user) {

    // JWT Authentication using Cookies
    // ================================
    // if (req.user) {

    // Passport Local Authentication
    // =============================
    if (req.user) {

        next();
    } else {
        res.status(401).json({message: 'Unauthorised access'});
    };
};

router.get('/', requireLogin, (req, res) => {
    res.render('users/users', {title: 'User registration'});
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
    res.render('users/login', {title: 'User login', csrfToken: req.csrfToken()});
});

// Passport Login (Form Submission)
// ================================
// router.post('/login', passport.authenticate('local', {
//     successRedirect: '/',
//     failureRedirect: '/users/login'
// }));

// Passport Login (AJAX)
// =====================
router.post('/login', upload.array(), passport.authenticate('local'), (req, res) => {
    res.json({message: 'logged in'})
});


// Express Session / JWT Authentication
// ====================================
// router.post('/login', async (req, res) => {
//     let [err, result] = await asyncf(User.authenticate(req.body.email, req.body.password));
//     if (err) {
//         res.send('Error finding user ' + err);
//     } else {
//         if (result !== false) {
//             // Express Session Authentication
//             // ==============================
//             // req.session.user = result;

//             // JWT Authentication with Express Session
//             // =======================================
//             // let token = await asyncf(bcrypt.hash(result.token, config.salt))
//             // req.session.token = token;

//             // JWT Authentication using Cookies
//             // ================================
//             res.cookie('token', result.token);

//             // Post-authentication action
//             res.redirect('/');
//         } else {
//             res.send('Incorrect password');
//         }
//     }
// });

router.get('/logout', (req, res) => {
    // Express Session Authentication
    // ==============================
    // delete req.session.user;
    // delete req.session.authenticated;
    // res.clearCookie('user_sid');

    // JWT Authentication with Express Session
    // =======================================
    // delete req.session.token;

    // JWT Authentication with Cookies
    // ===============================
    // res.clearCookie('token');

    // PassportJS
    // ==========
    req.logout();

    res.redirect('/');
})

module.exports = router;
