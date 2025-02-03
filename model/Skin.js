const mongoose = require('mongoose');
const { Schema } = mongoose;

const skinschema = new Schema ({
    name : String,
    price: Number, 
    url: String
});
mongoose.model('skins', skinschema);