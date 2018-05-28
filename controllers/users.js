const config = require('../config');
const express = require('express');
const router = express.Router();
const User = require('../models/user');
const auth = require('../lib/auth')(User);

// const asyncf = require('../async');
// const jwt = require('jsonwebtoken');
// const bcrypt = require('bcrypt');
const multer = require('multer');
const upload = multer();

const mailer = require('../lib/mail');

// let mailOptions = {
//     from: '"CK Dev Studios" <ckdevmnt@gmail.com>',
//     to: 'kok.chee.kean@outlook.com',
//     subject: 'Test Email',
//     text: 'Plain text body',
//     html: '<b>NodeJS Email Test</b>'
// };

// mailer.sendMail(mailOptions, (err, info) => {
//     if (err) {
//         return console.log(err);
//     };
//     console.log(info);
// })

router.get('/', (req, res) => {
    res.render('users/users', {
        title: 'User registration',
        websocketsEnabled: req.app.locals.websocketsEnabled
    });
});

router.get('/login', (req, res) => {
    res.render('users/login', {
        title: 'User login',
        csrfToken: req.csrfToken(),
        websocketsEnabled: req.app.locals.websocketsEnabled
    });
});

router.post('/', auth.register, (req, res) => {
    res.redirect('/');
});

router.post('/login', upload.array(), auth.login, (req, res) => {
    res.json({message: 'logged in'});
})

router.get('/logout', auth.logout, (req, res) => {
    res.redirect('/');
})

module.exports = router;
