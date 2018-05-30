const config = require('../config');
const express = require('express');
const router = express.Router();
const User = require('../models/user');
const auth = require('../lib/auth');
const TFA = require('../models/2fa');
const redirectTo = require('../lib/utils').redirectTo;
const returnJSON = require('../lib/utils').returnJSON;


// Example use of mailer
// =====================
const mailer = require('../lib/mail');
// let mailOptions = {
//     from: '"CK Dev Studios" <ckdevmnt@gmail.com>',
//     to: 'kok.chee.kean@outlook.com',
//     subject: 'Test Email',
//     text: 'Plain text body',
//     html: '<b>NodeJS Email Test</b>'
// };

// function mailtest (req, res, next) {
//     mailer.send(mailOptions, function(err, info) {
//         res.locals.sentTo = info.accepted;
//         next();
//     })
// };

router.get('/', (req, res) => {
    res.render('users/users', {
        title: 'User registration'
    });
});

router.get('/login', (req, res) => {
    res.render('users/login', {
        title: 'User login',
    });
});

router.get('/verify', async (req, res) => {
    let result = await User.verifyAccount(req.query.id, req.query.key);
    res.send(result);
})

router.get('/logout', auth.logout, redirectTo('/'));

router.get('/2fa', async (req, res) => {
    let user = null;
    if (req.session && req.session.user) {
        user = req.session.user;
    } else if (req.user) {
        user = req.user;
    } else {
        return res.redirect('/');
    };
    let result = await TFA.get(user._id);
    if (!result.secret.base32) {
        result = await TFA.create(user._id);
        res.render('users/2fa', {init: true, id: user._id, secret: result.secret.base32, imagelink: result.imagelink});
    } else {
        res.render('users/2fa', {init: false, id: user._id});
    }
});

router.get('/2fa/reset', async (req, res) => {
    let user = null;
    if (req.session && req.session.user) {
        user = req.session.user;
    } else if (req.user) {
        user = req.user;
    } else {
        res.redirect('/');
    };
    let result = await TFA.delete(user._id);
    res.redirect('/users/2fa');
})

router.post('/', auth.register, auth.verification, redirectTo('/'));

router.post('/login', auth.login, (req, res) => {
    if (config.TwoFactorAuthRequired === true) {
        res.redirect('/users/2fa');
    } else {
        res.redirect('/');
    };
});

router.post('/2fa', async (req, res) => {
    let result = await TFA.verify(req.body.id, req.body.key);
    if (result === true) {
        res.redirect('/');
    } else {
        res.redirect('/users/2fa');
    };
});

router.post('/upload', (req, res, next) => {
    res.send('Uploaded to ' + req.file.path);
})

module.exports = router;
