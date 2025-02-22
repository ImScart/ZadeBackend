const express = require('express');
const keys = require('./config/keys.js');
const app = express();
const bodyParser = require('body-parser');
const fs = require('fs').promises;
const portsFilePath = './ports.json';
const cors = require('cors');
const cookieParser = require('cookie-parser');

app.use(cors({
    origin: 'http://144.217.83.146',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials:true
}));

const resetPorts = async () => {
    try {
        const data = await fs.readFile(portsFilePath, 'utf8');
        
        let ports = JSON.parse(data);
        
        ports.forEach(port => port.inUse = false);
        ports.forEach(port => port.ownerUsername = null);
        ports.forEach(port => port.ownerId = null);
        
        await fs.writeFile(portsFilePath, JSON.stringify(ports, null, 2), 'utf8');
        console.log('All ports have been reset');
    } catch (err) {
        console.error('Error handling ports.json:', err);
    }
};

const startServer = async () => {
    await resetPorts();

    app.use(express.json());
    app.use(cookieParser());
    app.use(bodyParser.urlencoded({ extended: false }));

    const mongoose = require('mongoose');
    mongoose.connect(keys.mongoURI);

    require('./model/Account.js');
    require('./model/Skin.js');
    require('./routes/authRoutes.js')(app);

    app.listen(keys.port, () => {
        console.log("Port " + keys.port);
    });
};

startServer();
