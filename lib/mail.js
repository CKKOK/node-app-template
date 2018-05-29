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

let defaultMailOptions = {
    from: '"CK Dev Studios" <ckdevmnt@gmail.com>',
    to: 'ckdevmnt@gmail.com',
    subject: 'Default Email',
    text: 'You probably forgot to specify mail options',
    html: '<div><p>You probably forgot to specify mail options</p></div>'
};

function defaultCallback(err, info) {
    if (err) {
        return console.log(err);
    };
    console.log('Mail sent to:', info.accepted);
}

function send(mailOpts = defaultMailOptions, callback = defaultCallback) {
    transporter.sendMail(mailOpts, callback)
};

module.exports = {transporter, send};
