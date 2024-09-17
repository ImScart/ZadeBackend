const express = require('express');
const keys = require('./config/keys.js');
const app = express();
const bodyParser = require('body-parser');

app.use(bodyParser.urlencoded({extended: false}))

const mongoose = require('mongoose');
mongoose.connect(keys.mongoURI);

require('./model/Account.js');

require('./routes/authRoutes.js')(app);

app.listen(keys.port, () => {
    console.log("Port " + keys.port);
});