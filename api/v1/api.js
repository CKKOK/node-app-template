const config = require('../../config');
const express = require('express');
const router = express.Router();
const auth = require('../../lib/auth');

// Example use of Mailing Module
// =====================
// const mailer = require('../../lib/mail');
// let mailOptions = {
//     from: '"CK Dev Studios" <ckdevmnt@gmail.com>',
//     to: 'kok.chee.kean@outlook.com',
//     subject: 'Test Email',
//     text: 'Plain text body',
//     html: '<b>NodeJS Email Test</b>'
// };
// function (req, res, next) {
//     mailer.send(mailOptions, function(err, info) {
//         res.send(info);
//     })
// }

router.get('/', auth.require, (req, res) => {
    res.json({
        message: 'serve up data from your server here'
    })
});

module.exports = router;
