const speakeasy = require('speakeasy');
const secret = speakeasy.generateSecret({length: 20});
const asyncf = require('../async');
const qrcode = require('qrcode');

// Returns an object with the signature:
// { ascii: '', hex: '', base32: '', otpauth_url: '' }
function generateTFASecret(){
    return speakeasy.generateSecret({length: 20});
};

async function generateTFAQRCode(secret) {
    let result = await qrcode.toDataURL(secret.otpauth_url);
    return result;
};

function verify(secret, key) {
    let result = speakeasy.totp.verify({
        secret: secret.base32,
        encoding: 'base32',
        token: key
    });
    return result;
};

module.exports = {
    generateTFASecret,
    generateTFAQRCode,
    verify
};