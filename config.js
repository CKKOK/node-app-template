module.exports = {
    appName: 'authtest',

    serverDomain: 'localhost',

    serverEnv: 'development',
    // serverEnv: 'test',
    // serverEnv: 'production',

    // Protocol: 'http' or 'https'
    protocol: 'http',
    port: 3000,
    portSecure: 5000,

    // Enables / disables socket.io support
    websocketsEnabled: false,
    
    apikeys: {
        googleMaps: process.env.API_GMAP || '',
    },

    // Uncomment the address of the database in use
    // ========================================
    // db: 'postgres://kokcheekean@localhost:5432/authtest',
    db: 'mongodb://localhost:27017/authtest',

    salt: 10,

    jwtSecret: process.env.JWT_SECRET || '12345',
    
    // Should users who have not verified their emails be allowed to access the service?
    userVerificationRequired: true,

    // Should users be required to authenticate via 2FA before accessing the service?
    TwoFactorAuthRequired: false,

    // Authentication methods: Uncomment your chosen method
    // ====================================================
    // authMethod: 'express-session',
    authMethod: 'jwt-express-session',
    // authMethod: 'jwt-cookies',
    // authMethod: 'passport-jwt', // Only use this for pure API servers as this does not keep a session
    // authMethod: 'passport',
    authJWTExpirationTime: '3h',

    // Nodemailer Configuration
    // ========================
    mailFrom: 'CK Dev Studio <ckdevmnt@gmail.com>',
    mailHost: 'smtp.gmail.com',
    mailPort: 465,
    mailSecure: true,
    mailUsername: process.env.DEVMAILACCT || '',
    mailPassword: process.env.DEVMAILPASS || '',
}