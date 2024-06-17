const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const path = require('path');

const app = express();
const port = 3000;

const pool = new Pool({
  user: 'asset_user',
  host: 'localhost',
  database: 'asset_management',
  password: 'asset_password',
  port: 5432,
});

app.use(bodyParser.json());

// 静的ファイルを提供
app.use(express.static(path.join(__dirname, 'public')));

// ユーザー登録エンドポイント
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  try {
    const result = await pool.query(
      'INSERT INTO users (username, password) VALUES ($1, $2) RETURNING *',
      [username, hashedPassword]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ユーザーログインエンドポイント
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];
    if (user && (await bcrypt.compare(password, user.password))) {
      const token = jwt.sign({ id: user.id, username: user.username }, 'secret_key');
      res.json({ token });
    } else {
      res.status(400).json({ error: 'Invalid credentials' });
    }
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// 取引追加エンドポイント
app.post('/transactions', async (req, res) => {
  const { token, date, name, amount, type } = req.body;
  try {
    const decoded = jwt.verify(token, 'secret_key');
    const userId = decoded.id;
    const result = await pool.query(
      'INSERT INTO transactions (user_id, date, name, amount, type) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [userId, date, name, amount, type]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// 取引取得エンドポイント
app.get('/transactions', async (req, res) => {
  const { token } = req.query;
  try {
    const decoded = jwt.verify(token, 'secret_key');
    const userId = decoded.id;
    const result = await pool.query('SELECT * FROM transactions WHERE user_id = $1', [userId]);
    res.json(result.rows);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
