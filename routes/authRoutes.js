const mongoose = require('mongoose');
const Account = mongoose.model('accounts');
const Skin = mongoose.model('skins');
const moment = require('moment-timezone');
const argon2 = require('argon2');
var functions = require('../functions');
const jwt = require('jsonwebtoken');
const keys = require('../config/keys.js');
const { authenticate } = require('../functions.js');

const fs = require('fs');
const { spawn, exec } = require('child_process');
let ports = require('../ports.json');
const path = require('path');
const { userInfo } = require('os');
const scriptPath = path.join(__dirname, '../start_server.sh');

module.exports = app => {
    app.post('/auth/register', async (req, res) => {
        const { username, password } = req.body;
        if (!username || !password) {
            return res.status(400).send({
                code: 1,
                message: 'Invalid credentials'
            });
        }

        // Check if the username is already in use
        var userAccount = await Account.findOne({ username: username });

        // If no account exists, create a new one
        if (!userAccount) {
            console.log(username + ' is creating a new account');

            // Hash the password with argon2 (automatically generates a salt)
            const hash = await argon2.hash(password);

            var newAccount = new Account({
                username: username,
                password: hash, // Store the hashed password
                coins: 0,
                userIP: null,
                lastAuth: new Date(),
                refreshToken: null,
                isAdmin: false
            });

            await newAccount.save();

            // Send a success response
            return res.status(201).send({
                code: 0,
                message: 'success'
            });

        } else {
            // Username is already in use
            return res.status(409).send({
                code: 2,
                message: 'Username already exists'
            });
        }
    });

    app.post('/auth/login', async (req, res) => {
        const { username, password, rememberMe } = req.body;
        if (!username || !password || !rememberMe) {
            return res.status(400).send({
                code: 1,
                message: 'Invalid credentials'
            });
        }

        // Find the user account by username
        var userAccount = await Account.findOne({ username: username });

        // If there is no account with that username
        if (!userAccount) {
            return res.status(401).send({
                code: 1,
                message: 'Invalid credentials'
            });
        }

        // Verify the password
        const isMatch = await argon2.verify(userAccount.password, password);
        if (isMatch) {
            // Password is correct, proceed with login
            console.log('User ' + username + ' is logging in');

            // Update lastAuth field to the current time
            userAccount.lastAuth = new Date();

            // Generating access token (valid for 15 minutes)
            let accessToken;
            let refreshToken;
            if (rememberMe === '1') {
                accessToken = jwt.sign(
                    { id: userAccount._id.toString(), username: userAccount.username, tokenType: 'access' },
                    keys.secretKey,
                    { expiresIn: '15m' }
                );
                refreshToken = jwt.sign(
                    { id: userAccount._id.toString(), tokenType: 'refresh' },
                    keys.secretKey,
                    { expiresIn: '7d' }
                );

                // Store the refresh token in database
                userAccount.refreshToken = refreshToken;
            }
            await userAccount.save();

            // Preparing response data
            let responseData = {
                code: 0,
                message: 'success',
                id: userAccount.id,
                username: userAccount.username,
                coins: userAccount.coins,
                userIP: userAccount.userIP,
                lastAuth: moment(userAccount.lastAuth).tz("America/New_York").format('YYYY-MM-DD HH:mm:ss'),
                isAdmin: userAccount.isAdmin
            };

            if (rememberMe === '1') {
                responseData.accessToken = accessToken;
                // Refresh token is sent as a cookie
            }
            res.cookie('refreshToken', refreshToken, {
                httpOnly: true,
                secure: true,
                sameSite: 'Strict',
                maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
            });
            return res.status(200).send(responseData);
        }
        else {
            // Password is incorrect
            return res.status(401).send({
                code: 1,
                message: 'Invalid credentials'
            });
        }
    });

    // Refresh access token
    app.post('/auth/refresh', async (req, res) => {
        const { refreshToken } = req.body;
        if (!refreshToken) {
            return res.status(401).send(
                {
                    code: 1,
                    message: 'Refresh token required'
                });
        }

        await jwt.verify(refreshToken, keys.secretKey, async (err, decoded) => {
            if (err && err.name === 'TokenExpiredError') {
                return res.status(403).send({
                    code: 3,
                    message: 'Refresh token has expired'
                });
            }
            if (err || decoded.tokenType != 'refresh') {
                return res.status(401).send(
                    {
                        code: 1,
                        message: 'Invalid refresh token'
                    }
                );
            }
            // Try to find the user
            const userAccount = await Account.findOne({ _id: decoded.id, refreshToken: refreshToken });
            // No user found
            if (!userAccount) {
                return res.status(401).send(
                    {
                        code: 1,
                        message: 'Invalid refresh token'
                    }
                );
            }
            const accessToken = jwt.sign(
                { id: userAccount._id.toString(), username: userAccount.username, tokenType: 'access' },
                keys.secretKey,
                { expiresIn: '15m' }
            );

            const newRefreshToken = jwt.sign(
                { id: userAccount._id.toString(), tokenType: 'refresh' },
                keys.secretKey,
                { expiresIn: '7d' }
            );
            userAccount.refreshToken = newRefreshToken;
            await userAccount.save();

            return res.status(200).send({
                code: 0,
                message: 'success',
                accessToken: accessToken,
                refreshToken: newRefreshToken
            });
        });
    });

    app.post('/auth/logout', authenticate, async (req, res) => {
        const userId = req.decoded.id;
        const userAccount = await Account.findOne({ _id: req.user.id });
        if (!userAccount) {
            return res.status(401).send({
                code: 1,
                message: 'Invalid credentials'
            });
        }
        console.log('User ' + req.decoded.username + ' is logging out');
        userAccount.refreshToken = null;
        await userAccount.save();
        return res.status(200).send({
            code: 0,
            message: 'success'
        })
    });

    // Protected with access token. Placeholder
    app.get('/account/checkcoins', authenticate, async (req, res) => {
        const userId = req.decoded.id;
        const userAccount = await Account.findOne({ _id: userId });
        if (!userAccount) {
            return res.status(401).send({
                code: 1,
                mesasge: 'Invalid credentials'
            });
        }
        res.status(200).send({
            code: 0,
            message: 'success',
            coins: userAccount.coins
        });
    });
    // Start a new server
    app.post('/servers', authenticate, async (req, res) => {
        const userId = req.decoded.id;
        const userAccount = await Account.findOne({ _id: userId });
        if (!userAccount) {
            return res.status(401).send({
                code: 1,
                mesasge: 'Invalid credentials'
            });
        }
        if (userAccount.coins < 1) {
            return res.status(402).send({
                code: 4,
                message: 'User does not have enough coins to create a new server'
            });
        }
        const availablePort = ports.find(p => !p.inUse);
        if (!availablePort) {
            return res.status(409).send(
                {
                    code: 5,
                    error: 'Servers are full. Please try again later.'
                });
        }
        const serverProcess = spawn('bash', [scriptPath, availablePort.port]);

        serverProcess.stderr.on('data', (data) => {
            console.error(`stderr: ${data}`);
        });

        serverProcess.on('close', async (code) => {
            if (code === 0) {
                availablePort.inUse = true;
                availablePort.ownerUsername = userAccount.username;
                availablePort.ownerId = userAccount._id;
                availablePort.startTime = moment(userAccount.lastAuth).tz("America/New_York").format('YYYY-MM-DD HH:mm:ss');
                fs.writeFileSync('./ports.json', JSON.stringify(ports, null, 2));
                userAccount.coins--;
                await userAccount.save();
                console.log('User ' + userAccount.username + ' started a server on port ' + availablePort.port);
                return res.send({
                    code: 0,
                    message: 'Server started on port: ' + availablePort.port
                });
            } else {
                res.status(500).send(
                    {
                        code: 6,
                        error: 'Failed to start server.'
                    });
            }
        });
    });
    // Get all servers
    app.get('/servers', authenticate, async (req, res) => {
        const userId = req.decoded.id;
        const userAccount = await Account.findOne({ _id: userId });
        if (!userAccount) {
            return res.status(401).send({
                code: 1,
                message: 'Invalid credentials'
            });
        }
        const activeServers = ports.filter(p => p.inUse);
        const minimalServers = activeServers.map(server => ({
            port: server.port,
            ownerUsername: server.ownerUsername,
            startTime: server.startTime
        }));
        return res.status(200).send({
            code: 0,
            message: 'success',
            servers: minimalServers
        });
    });
    // Stop a server
    app.delete('/servers', authenticate, async (req, res) => {
        const { serverPort } = req.body;
        if (!serverPort) {
            return res.status(401).send(
                {
                    code: 1,
                    message: 'Invalid server port'
                }
            );
        }
        const serverPortInfo = ports.find(p => p.port === parseInt(serverPort, 10));
        if (serverPortInfo.inUse == false) {
            return res.status(404).send(
                {
                    code: 7,
                    message: 'Server is not currently in use'
                }
            );
        }
        const userId = req.decoded.id;
        const userAccount = await Account.findOne({ _id: userId });
        if (!userAccount) {
            return res.status(401).send({
                code: 1,
                message: 'Invalid credentials'
            });
        }
        if (serverPortInfo.ownerId.toString() != userAccount._id.toString()) {
            return res.status(403).send(
                {
                    code: 8,
                    message: 'User is not the owner of the server.'
                }
            );
        }
        // Kill the process with port
        exec(`fuser -k ${serverPortInfo.port}/tcp`, async (error, stdout, stderr) => {
            if (error) {
                console.error(`Error stopping server on port ${port}:`, stderr);
                return res.status(500).json({ error: `Failed to stop server on port ${serverPortInfo.port}` });
            }
            console.log('User ' + userAccount.username + ' stopped a server on port ' + serverPortInfo.port);

            // Update the port status to not in use
            serverPortInfo.inUse = false;
            serverPortInfo.ownerUsername = null;
            serverPortInfo.ownerId = null;
            await fs.writeFileSync('./ports.json', JSON.stringify(ports, null, 2));
            return res.status(200).send(
                {
                    code: 0,
                    message: 'Server on port ' + serverPortInfo.port + ' has been shut down.'
                }
            );
        });

    });

    app.post('/skins/populate', authenticate, async (req, res) => {
        const userId = req.decoded.id;
        const userAccount = await Account.findOne({ _id: userId });
        if (!userAccount) {
            return res.status(401).send({
                code: 1,
                message: 'Invalid credentials'
            });
        }
        if (userAccount.isAdmin != true) {
            return res.status(403).send({
                code: 8,
                message: 'Admin permissions needed'
            });
        }
        const seedSkins = async () => {
            try {
                // Array of skins to add
                const skinsData = [
                    { name: 'pokerface', price: 5, url: 'http://144.217.83.146/skins/pokerface.png' },
                    { name: 'doge', price: 10, url: 'http://144.217.83.146/skins/doge.png' }
                ];

                // Insert them
                await Skin.insertMany(skinsData);
                return res.status(201).send({
                    code: 0,
                    message: 'Skins seeded successfully!'
                });
            } catch (err) {
                return res.status(500).send({
                    code: 9,
                    message: 'An unexpected error occurred.'
                });
            }
        };

        // Run the seed function
        await seedSkins();
    });

    app.post('/skins/add', authenticate, async (req, res) => {
        const { name, price, url } = req.body;
        if (!name || !price || !url) {
            return res.status(400).send({
                code: 1,
                message: 'Invalid Skin Values'
            });
        }
        const userId = req.decoded.id;
        const userAccount = await Account.findOne({ _id: userId });
        if (!userAccount) {
            return res.status(401).send({
                code: 1,
                message: 'Invalid credentials'
            });
        }
        if (userAccount.isAdmin != true) {
            return res.status(403).send({
                code: 8,
                message: 'Admin permissions needed'
            });
        }
        // Check for existing skin by name
        const skinName = await Skin.findOne({ name });
        if (skinName) {
            return res.status(409).send({
                code: 10,
                message: 'Skin name already exists'
            });
        }
        // Check for existing skin by URL
        const skinUrl = await Skin.findOne({ url });
        if (skinUrl) {
            return res.status(409).send({
                code: 10,
                message: 'Skin URL already exists'
            });
        }
        // Add the skin
        try {
            await Skin.create({ name, price, url });
            return res.status(201).send({
                code: 0,
                message: 'Skin added successfully!'
            });
        } catch (err) {
            return res.status(500).send({
                code: 9,
                message: 'An unexpected error occurred.'
            });
        }
    });
    app.delete('/skins/delete', authenticate, async (req, res) => {
        const userId = req.decoded.id;
        const { name } = req.body;
        if (!name) {
            return res.status(400).send({
                code: 1,
                message: 'Invalid skin name'
            });
        }
        const userAccount = await Account.findOne({ _id: userId });
        if (!userAccount) {
            return res.status(401).send({
                code: 1,
                message: 'Invalid credentials'
            });
        }
        if (userAccount.isAdmin != true) {
            return res.status(403).send({
                code: 8,
                message: 'Admin permissions needed'
            });
        }
        const skinToDelete = await Skin.findOne({ name });
        if (!skinToDelete) {
            return res.status(400).send({
                code: 1,
                message: 'Skin name not found'
            });
        }
        // Delete the skin
        try {
            await Skin.deleteOne(skinToDelete);
            return res.status(200).send({
                code: 0,
                message: 'Skin deleted successfully!'
            });
        } catch (err) {
            return res.status(500).send({
                code: 9,
                message: 'An unexpected error occurred.'
            });
        }
    });
    app.get('/skins/getAll', async (req, res) => {
        try {
            const skins = await Skin.find({}, 'name price url');
            return res.status(200).send(skins);
        }
        catch (err) {
            return res.status(500).send({
                code: 9,
                message: 'An unexpected error occurred.'
            })
        }
    });
    app.post('/skins/purchase', authenticate, async (req, res) => {
        const { skinName } = req.body;
        if (!skinName) {
            return res.status(400).send({
                code: 1,
                message: 'Invalid skin name'
            });
        }
        const userId = req.decoded.id;
        const userAccount = await Account.findOne({ _id: userId });
        if (!userAccount) {
            return res.status(401).send({
                code: 1,
                message: 'Invalid credentials'
            });
        }
        const skin = await Skin.findOne({ name: skinName });
        if (!skin) {
            return res.status(400).send({
                code: 1,
                message: 'Invalid skin name'
            });
        }
        if (userAccount.skins.some(s => s.toString() === skin._id.toString())) {
            return res.status(409).send({
                code: 11,
                message: 'User already owns this skin'
            });
        }
        try {
            await userAccount.skins.push(skin);
            userAccount.save();
        }
        catch (err) {
            return res.status(500).send({
                code: 9,
                message: err //'An unexpected error occurred.'
            });
        }


        return res.status(200).send({
            code: 0,
            message: 'Success'
        });
    });
    app.get('/skins/getMy', authenticate, async (req, res) => {
        const userId = req.decoded.id;

        const userAccount = await Account.findOne({_id: userId});
        if(!userAccount)
        {
            return res.status(401).send({
                code: 1,
                message: 'Invalid credentials'
            });
        }

        return res.status(200).send(userAccount.skins);
    });
};
