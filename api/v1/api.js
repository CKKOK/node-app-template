const config = require('../../config');
const express = require('express');
const router = express.Router();
const User = require('../../models/user');
const auth = require('../../lib/auth')(User);

// const asyncf = require('../async');
// const jwt = require('jsonwebtoken');
// const bcrypt = require('bcrypt');
const multer = require('multer');
const upload = multer();

const mailer = require('../../lib/mail');

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

router.get('/', auth.checkForAuth, (req, res) => {
    res.json({
        message: 'serve up data from your server here'
    })
});

module.exports = router;
