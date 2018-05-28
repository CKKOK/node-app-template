const express = require('express');
const router = express.Router();

router.get('/', (req, res) => {
    let context = {websocketsEnabled: req.app.locals.websocketsEnabled};
    if (req.session.user || req.user || (req.isAuthenticated && req.isAuthenticated())) {
        context.defaultMessage = 'hello, you\'re logged in';
    } else {
        context.defaultMessage = 'hello, you\'re NOT logged in';
    };
    res.render('index', context);
})

module.exports = router;