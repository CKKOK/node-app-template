const express = require('express');
const router = express.Router();

router.get('/', (req, res) => {
    if (req.session.user || req.user || (req.isAuthenticated && req.isAuthenticated())) {
        res.locals.defaultMessage = 'Hello, you\'re logged in';
    } else {
        res.locals.defaultMessage = 'Hello, you\'re NOT logged in';
    };
    res.render('index');
})

module.exports = router;