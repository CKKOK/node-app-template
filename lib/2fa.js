const speakeasy = require('speakeasy');
const secret = speakeasy.generateSecret({length: 20});

const qrcode = require('qrcode');

// console.log(secret.base32); // Should store this in user database

qrcode.toDataURL(secret.otpauth_url, function(err, image_data) {
    // console.log(image_data); // This goes into the img src, to be scanned into the authenticator app
});

const userSecret = secret.base32; // Should retrieve this from user database

const token = speakeasy.totp({
    secret: 'KY7USJJXI52UWPRYFZNU6QCCF43VCMKN',
    encoding: 'base32'
});

console.log(token)

// const userToken = params.get('token'); // Given by the user via POST form

// const verified = speakeasy.totp.verify({
//     secret: secret,
//     encoding: 'base32',
//     token: userToken
// })