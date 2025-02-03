const mongoose = require('mongoose');
const { Schema } = mongoose;

const accountschema = new Schema({
    id: String,
    username: String,
    password: String,
    refreshToken: String,

    coins:Number,
    skins: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Skin' }],
    userIP:String,
    lastAuth: Date,

    isAdmin: Boolean
});

mongoose.model('accounts', accountschema);