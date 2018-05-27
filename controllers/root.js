const express = require('express');
const router = express.Router();

router.get('/', (req, res) => {
    let context = {};
    if (req.session.authenticated === true || req.user) {
        context.defaultMessage = 'hello, you\'re logged in';
    } else {
        context.defaultMessage = 'hello, you\'re NOT logged in';
    };
    res.render('index', context);
})

module.exports = router;