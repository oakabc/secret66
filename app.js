require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const flash = require('connect-flash');
const path = require('path');

const app = express();
const port = 3000;

// Middleware
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(
  session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false,
  })
);
app.use(flash());

// Database connection
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

db.connect((err) => {
  if (err) throw err;
  console.log('Connected to MySQL Database!');
});

// Routes
app.get('/', (req, res) => {
  res.render('home');
});

app.get('/register', (req, res) => {
  res.render('register', { message: req.flash('message') });
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  const query = 'INSERT INTO users (email, password) VALUES (?, ?)';
  db.query(query, [username, hashedPassword], (err, result) => {
    if (err) {
      req.flash('message', 'User already exists!');
      return res.redirect('/register');
    }
    res.redirect('/login');
  });
});

app.get('/login', (req, res) => {
  res.render('login', { message: req.flash('message') });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  const query = 'SELECT * FROM users WHERE email = ?';
  db.query(query, [username], async (err, results) => {
    if (err || results.length === 0) {
      req.flash('message', 'Invalid email or password!');
      return res.redirect('/login');
    }

    const user = results[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (isMatch) {
      req.session.userId = user.id;
      res.redirect('/secrets');
    } else {
      req.flash('message', 'Invalid email or password!');
      res.redirect('/login');
    }
  });
});

app.get('/secrets', (req, res) => {
  if (!req.session.userId) return res.redirect('/login');
  res.render('secrets');
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

// Submit secrets route (optional)
app.post('/submit', (req, res) => {
  // Logic for handling secrets submission
  res.redirect('/secrets');
});

// Start server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
