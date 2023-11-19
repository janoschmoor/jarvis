const express = require('express');
const http = require('http');
const socketIO = require('socket.io');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const session = require('express-session');
const bcrypt = require('bcrypt');
const fs = require('fs');
const passportSocketIo = require('passport.socketio');


class Server {
    constructor() {
        this.app = express();
        this.server = http.createServer(this.app);
        this.io = socketIO(this.server);
        this.PORT = process.env.PORT || 3000;

        this.setupMiddleware();
        this.setupPassport();
        this.setupRoutes();
    }

    setupMiddleware() {
        // Serve static files from the 'public' directory
        this.app.use(express.static('public'));
        // Set up session and passport
        this.app.use(session({ secret: 'your-secret-key', resave: true, saveUninitialized: true }));
        this.app.use(passport.initialize());
        this.app.use(passport.session());
    }

    setupPassport() {
        // Sample user data (you would replace this with a database)
        this.users = [
            { id: 1, username: 'user1', password: '$2b$10$E1aPKzMFesIT2PVaEF0nruNRv8m/EQ6kx67wuCso1OvCwoUvL3FHu', apiKey: 'api_key_1' },
            // Add more users as needed
        ];

        // Passport configuration
        passport.use(new LocalStrategy(
            (username, password, done) => {
                const user = this.users.find(u => u.username === username);

                if (!user) {
                    return done(null, false, { message: 'Incorrect username.' });
                }

                // Check the password using bcrypt
                bcrypt.compare(password, user.password, (err, res) => {
                    if (res) {
                        return done(null, user);
                    } else {
                        return done(null, false, { message: 'Incorrect password.' });
                    }
                });
            }
        ));

        passport.serializeUser((user, done) => {
            done(null, user.id);
        });

        passport.deserializeUser((id, done) => {
            const user = this.users.find(u => u.id === id);
            done(null, user);
        });
    }

    setupRoutes() {
        // Set up a connection event
        this.io.on('connection', (socket) => {
            console.log('A user connected');

            // Handle registration of new users
socket.on('register', (userData) => {
    console.log('User registered:', userData);

    // Check if the username is already taken
    if (this.users.some(user => user.username === userData.name)) {
        return socket.emit('registrationFailed', 'Username is already taken.');
    }

    // Hash the password using bcrypt
    bcrypt.hash(userData.password, 10, (err, hash) => {
        if (err) throw err;

        // Add the hashed password to the user data
        const newUser = {
            id: this.users.length + 1,
            username: userData.name,
            password: hash,
            apiKey: userData.apiKey,
            // Additional user data for the dashboard
            dashboardData: {
                // Add more properties as needed
            },
        };

        // Add user data to the in-memory array
        this.users.push(newUser);

        // Write user data to a JSON file
        this.writeUserDataToFile(this.users);

        // Authenticate the new user
        socket.request.session.passport = { user: newUser.id };

        // Send a success signal to the client
        socket.emit('registrationSuccess', 'Registration successful.');

        // Broadcast the updated user list to all connected clients
        this.io.emit('userList', this.users.map(user => user.username));
    });
});



            // Handle authentication
            socket.on('authenticate', (credentials, callback) => {
                passport.authenticate('local', (err, user, info) => {
                    if (err) { return callback(err); }
                    if (!user) { return callback('Authentication failed.'); }

                    // Log in the user
                    socket.request.logIn(user, (err) => {
                        if (err) { return callback(err); }

                        // Send the user data to the client for the dashboard
                        socket.emit('userData', user);

                        // Send a success signal to the client
                        return callback(null, 'Authentication succeeded.');
                    });
                })(credentials);
            });

            // Handle messages from the authenticated client
            socket.on('authenticated-message', (msg) => {
                console.log(`Authenticated Message: ${msg}`);
                // Broadcast the message to all connected clients
                this.io.emit('chat message', msg);
            });

            // Handle disconnection
            socket.on('disconnect', () => {
                console.log('User disconnected');
            });
        });
    }

    writeUserDataToFile(userData) {
        const jsonUserData = JSON.stringify(userData, null, 2);

        // Specify the path to the JSON file
        const filePath = 'user_data.json';

        // Write to the file
        fs.writeFileSync(filePath, jsonUserData);

        console.log('User data written to file:', filePath);
    }

    start() {
        // Start the server
        this.server.listen(this.PORT, () => {
            console.log(`Server is listening on port ${this.PORT}`);
        });
    }
}

module.exports = Server;

// Example usage:
// const MyServer = new Server();
// MyServer.start();
