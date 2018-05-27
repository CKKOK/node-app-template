const config = require('./config');

const redis = require('redis');
const redisClient = redis.createClient();
const express = require('express');

// const viewEngine = require('ejs-locals');
const viewEngine = require('express-handlebars');

// const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const methodOverride = require('method-override');

// JWT Authentication
// const jwt = require('jsonwebtoken');


// Express Session Authentication
const session = require('express-session');
const redisStore = require('connect-redis')(session);

const logger = require('morgan');
const path = require('path');
const server = express();

const csrf = require('csurf');
const csrfProtection = csrf({cookie: true});

// Enable request logging
server.use(logger('dev'));

// Enables overriding of http verbs for supporting PUT/PATCH and DELETE requests from older clients
server.use(methodOverride('_method'));

// server.use(bodyParser.json());
// server.use(bodyParser.urlencoded({
//     extended: true
// }));
server.use(express.json());
server.use(express.urlencoded({extended: true}));
server.use(cookieParser());

// Set up express-session
server.use(session({
    key: 'user_sid',
    secret: '12345',
    resave: false,
    saveUninitialized: false,
    cookie: {
        expires: 600000
    },
    store: new redisStore({
        host: 'localhost',
        port: 6379,
        client: redisClient,
        ttl: 260
    })
}));

// const passport = require('./models/user').passport;
// server.use(passport.initialize());
// server.use(passport.session());
const User = require('./models/user');
const auth = require('./lib/auth')(User, server);

// Cross Site Resource Forgery Protection
server.use(csrfProtection);

// Set up view engine and static asset paths
server.set('views', path.join(__dirname, 'views'));

// Use EJS
// server.engine('ejs', viewEngine);
// server.set('view engine', 'ejs');

// Use Handlebars
server.engine('hbs', viewEngine.create({
    extname: '.hbs',
    defaultLayout: 'default',
    partialsDir: path.join(__dirname, 'views', 'partials'),
    layoutsDir: path.join(__dirname, 'views', 'layouts'),
}).engine);
server.set('view engine', 'hbs');

// Configure path to static assets
server.use(express.static(path.join(__dirname, 'public')));

// Express Session Authentication: Check if this session contains an authenticated user
// ====================================================================================
// server.use((req, res, next) => {
//     if (req.cookies.user_sid) {
//         if (req.session.user) {
//             req.session.authenticated = true;
//         } else {
//             res.clearCookie('user_sid');
//         };
//     };
//     next();
// });

// JWT Authentication with Express Session: Check if this session contains a JWT
// =============================================================================
// server.use((req, res, next) => {
//     if (req.session.token) {
//         jwt.verify(req.session.token, config.jwtSecret, (err, decodedToken) => {
//             if (err) {
//                 req.user = undefined;
//             } else {
//                 req.user = decodedToken;
//             };
//             next();
//         });
//     } else {
//         req.user = undefined;
//         next();
//     }
// })

// JWT Authentication with Cookies: Check if the cookies contains a JWT
// server.use((req, res, next) => {
//     if (req.cookies.token) {
//         jwt.verify(req.cookies.token, config.jwtSecret, (err, decodedToken) => {
//             if (err) {
//                 req.user = undefined;
//             } else {
//                 req.user = decodedToken;
//             };
//             next();
//         });
//     } else {
//         // req.user = undefined;
//         next();
//     }
// })


// WebSockets Configuration: Pass the status on to the application level to cascade down to the response level
// ===========================================================================================================
server.locals.websocketsEnabled = config.websocketsEnabled;

// Routers
const root = require('./controllers/root');
const users = require('./controllers/users');

server.use('/', root);
server.use('/users', users);

module.exports = server;
