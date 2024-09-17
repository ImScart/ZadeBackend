const mongoose = require('mongoose');
const { Schema } = mongoose;

const accountschema = new Schema({
    username: String,
    password: String,

    coins:String,
    userIP:String,
    lastAuth: Date
});

mongoose.model('accounts', accountschema);