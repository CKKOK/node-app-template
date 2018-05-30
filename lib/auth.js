const config = require('../config');

let toExport = null;

switch(config.authMethod) {
    case 'express-session':
        console.log('User authentication: express-session');
        toExport = require('./auth/expressSession');
        break;
    case 'jwt-express-session':
        console.log('User authentication: jwt-express-session');    
        toExport = require('./auth/jwtExpressSession');
        break;
    case 'jwt-cookies':
        console.log('User authentication: jwt-cookies');
        toExport = require('./auth/jwtCookies');
        break;
    case 'passport-jwt':
        console.log('User authentication: passport-jwt');
        toExport = require('./auth/passportJwt');
        break;
    case 'passport':
        console.log('User authentication: passport');
        toExport = require('./auth/passport');
        break;
    default:
        console.log('User authentication library not set');
        break;
}

module.exports = toExport;
