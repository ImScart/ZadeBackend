const mongoose = require('mongoose');
const { Schema } = mongoose;

const accountschema = new Schema({
    id: String,
    username: String,
    password: String,
    refreshToken: String,

    coins:String,
    userIP:String,
    lastAuth: Date
});

mongoose.model('accounts', accountschema);