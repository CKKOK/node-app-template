module.exports = {
    port: 3000,
    securePort: 5000,

    // db: 'postgres://kokcheekean@localhost:5432/authtest',
    db: 'mongodb://localhost:27017/authtest',

    salt: 10,

    jwtSecret: '12345',
    
    authMethod: 'express-session',
    // authMethod: 'jwt-express-session',
    // authMethod: 'jwt-cookies',
    // authMethod: 'passport-jwt',
    // authMethod: 'passport',
}