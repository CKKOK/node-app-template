module.exports = {
    appName: 'authtest',

    protocol: 'http',
    port: 3000,
    portSecure: 5000,

    websocketsEnabled: false,
    
    apikeys: {
        googleMaps: process.env.API_GMAP || '',
    },

    // db: 'postgres://kokcheekean@localhost:5432/authtest',
    db: 'mongodb://localhost:27017/authtest',

    salt: 10,

    jwtSecret: process.env.JWT_SECRET || '12345',
    
    userVerificationRequired: false,

    authMethod: 'express-session',
    // authMethod: 'jwt-express-session',
    // authMethod: 'jwt-cookies',
    // authMethod: 'passport-jwt',
    // authMethod: 'passport',

    mailHost: 'smtp.gmail.com',
    mailPort: 465,
    mailSecure: true,
    mailUsername: process.env.DEVMAILACCT || '',
    mailPassword: process.env.DEVMAILPASS || '',
}