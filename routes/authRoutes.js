const mongoose = require('mongoose');
const Account = mongoose.model('accounts');
const moment = require('moment-timezone');
const argon2 = require('argon2');

module.exports = app => {
    app.post('/register', async (req, res) => {
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
                    lastAuth: new Date()
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

    app.post('/login', async (req, res) => {
        const { username, password } = req.body;

        if (!username || !password) {
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
                await userAccount.save();

                // Send the user account data with formatted lastAuth
                return res.send({
                    code: 0,
                    message: 'success',
                    id: userAccount.id,
                    username: userAccount.username,
                    coins: userAccount.coins,
                    userIP: userAccount.userIP,
                    lastAuth: moment(userAccount.lastAuth).tz("America/New_York").format('YYYY-MM-DD HH:mm:ss')  // EST time instead of UTC
                });
            } else {
                // Password is incorrect
                return res.send({
                    code: 1,
                    message: 'Invalid credentials'
                });
            }
    });
};
