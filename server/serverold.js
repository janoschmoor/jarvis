

// Serve static files from the 'public' directory
app.use(express.static('public'));

// Set up session and passport
app.use(session({ secret: 'your-secret-key', resave: true, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());

// Sample user data (you would replace this with a database)
const users = [
  { id: 1, username: 'user1', password: '$2b$10$E1aPKzMFesIT2PVaEF0nruNRv8m/EQ6kx67wuCso1OvCwoUvL3FHu', apiKey: 'api_key_1' },
  // Add more users as needed
];

// Passport configuration
passport.use(new LocalStrategy(
  (username, password, done) => {
    const user = users.find(u => u.username === username);

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
  const user = users.find(u => u.id === id);
  done(null, user);
});

// Set up a connection event
io.on('connection', (socket) => {
  console.log('A user connected');

  // Handle registration of new users
  socket.on('register', (userData) => {
    console.log('User registered:', userData);

    // Hash the password using bcrypt
    bcrypt.hash(userData.password, 10, (err, hash) => {
      if (err) throw err;

      // Add the hashed password to the user data
      const newUser = {
        id: users.length + 1,
        username: userData.name,
        password: hash,
        apiKey: userData.apiKey,
      };

      // Add user data to the in-memory array
      users.push(newUser);

      // Write user data to a JSON file
      writeUserDataToFile(users);

      // Broadcast the updated user list to all connected clients
      io.emit('userList', users.map(user => user.username));
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
        return callback(null, 'Authentication succeeded.');
      });
    })(credentials);
  });

  // Handle messages from the authenticated client
  socket.on('authenticated-message', (msg) => {
    console.log(`Authenticated Message: ${msg}`);
    // Broadcast the message to all connected clients
    io.emit('chat message', msg);
  });

  // Handle disconnection
  socket.on('disconnect', () => {
    console.log('User disconnected');
  });
});

// Function to write user data to a JSON file
function writeUserDataToFile(userData) {
  const jsonUserData = JSON.stringify(userData, null, 2);

  // Specify the path to the JSON file
  const filePath = 'user_data.json';

  // Write to the file
  fs.writeFileSync(filePath, jsonUserData);

  console.log('User data written to file:', filePath);
}

// Start the server
server.listen(PORT, () => {
  console.log(`Server is listening on port ${PORT}`);
});
