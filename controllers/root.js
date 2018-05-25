const express = require('express');
const router = express.Router();

router.get('/', (req, res) => {
    if (req.session.authenticated === true) {
        res.send('hello, you\'re logged in');
    } else {
        res.send('hello, you\'re NOT logged in');
    };
})

module.exports = router;