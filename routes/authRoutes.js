const mongoose = require('mongoose');
const Account = mongoose.model('accounts');
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
const scriptPath = path.join(__dirname, '../start_server.sh');

module.exports = app => {
    app.post('/auth/register', async (req, res) => {
        const { username, password } = req.body;
        if (!username || !password) {
            return res.send({
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
                refreshToken: null
            });

            await newAccount.save();

            // Send a success response
            return res.send({
                code: 0,
                message: 'success'
            });

        } else {
            // Username is already in use
            return res.send({
                code: 2,
                message: 'Username already exists'
            });
        }
    });

    app.post('/auth/login', async (req, res) => {
        const { username, password, rememberMe } = req.body;

        if (!username || !password || !rememberMe) {
            return res.send({
                code: 1,
                message: 'Invalid credentials'
            });
        }

        // Find the user account by username
        var userAccount = await Account.findOne({ username: username });

        // If there is no account with that username
        if (!userAccount) {
            return res.send({
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
                lastAuth: moment(userAccount.lastAuth).tz("America/New_York").format('YYYY-MM-DD HH:mm:ss')
            };

            if (rememberMe === '1') {
                responseData.accessToken = accessToken;
                responseData.refreshToken = refreshToken;
            }
            // Send the user account data with formatted lastAuth
            return res.send(responseData);
        }
        else {
            // Password is incorrect
            return res.send({
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
            if (err || decoded.tokenType != 'refresh') {
                return res.status(403).send(
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
                return res.status(403).send(
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

            return res.send({
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
            return res.status(400).send({
                code: 1,
                mesasge: 'User not found'
            });
        }
        console.log('User ' + req.decoded.username + ' is logging out');
        userAccount.refreshToken = null;
        await userAccount.save();
        return res.send({
            code: 0,
            message: 'success'
        })
    });

    // Protected with access token. Placeholder
    app.get('/account/checkcoins', authenticate, async (req, res) => {
        const userId = req.decoded.id;
        const userAccount = await Account.findOne({ _id: userId });
        if (!userAccount) {
            return res.status(400).send({
                code: 1,
                mesasge: 'User not found'
            });
        }
        res.send({
            code: 0,
            message: 'success',
            coins: userAccount.coins
        });
    });
	// Start a new server
    app.post('/servers', authenticate, async(req, res) => {
        const userId = req.decoded.id;
        const userAccount = await Account.findOne({_id: userId});
        if (!userAccount) {
            return res.status(400).send({
                code: 1,
                mesasge: 'User not found'
            });
        }
        if(userAccount.coins<1){
            return res.status(403).send({
                code: 2,
                message: 'User does not have enough coins to create a new server'
            });
        }
        const availablePort = ports.find(p => !p.inUse);
        if (!availablePort) {
            return res.status(400).json({ error: 'Servers are full. Please try again later.' });
        }
		const serverProcess = spawn('bash', [scriptPath, availablePort.port]);	
    
        serverProcess.stderr.on('data', (data) => {
            console.error(`stderr: ${data}`);
        }); 

        serverProcess.on('close', async (code) => {
            if (code === 0) {
                availablePort.inUse = true;
                fs.writeFileSync('./ports.json', JSON.stringify(ports, null, 2));
                userAccount.coins--;
                await userAccount.save();
                console.log('User '+ userAccount.username + ' started a server on port '+availablePort.port);
                return res.send({
                    code:0,
                    message: 'Server started on port: '+ availablePort.port
                });
            } else {
                res.status(500).json({ error: 'Failed to start server.' });
            }
        });
    });
};
