const config = require('../config');
const mailer = require('nodemailer');
const mailConfig = {
    host: config.mailHost,
    port: config.mailPort,
    secure: config.mailSecure,
    auth: {
        user: config.mailUsername,
        pass: config.mailPassword
    }
};

const transporter = mailer.createTransport(mailConfig);

module.exports = transporter;
