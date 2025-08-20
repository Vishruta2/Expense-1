const express = require('express');
const fs = require('fs');
const path = require('path');
const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static(__dirname)); // serves index.html

const USERS_FILE = path.join(__dirname, 'users.txt'); // move outside if possible

function loadUsers() {
  const text = fs.readFileSync(USERS_FILE, 'utf8');
  const map = new Map();
  text.split('\n').forEach(line => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) return;
    const [user, pass] = trimmed.split(',', 2).map(s => s.trim());
    if (user && pass) map.set(user, pass);
  });
  return map;
}

app.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).send('Missing username or password.');
  }

  try {
    const users = loadUsers();
    const expected = users.get(username);
    if (expected && expected === password) {
      return res.send('Login successful!');
      // res.redirect('/dashboard.html');
    }
    return res.status(401).send('Invalid username or password.');
  } catch (e) {
    console.error(e);
    return res.status(500).send('Server error.');
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Listening on http://localhost:${PORT}`));
