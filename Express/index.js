const express = require('express');
const mongoose = require('mongoose');
const User = require('./models/User');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = 5001;
const MONGO_URI = 'mongodb://localhost:27017/mydatabase';
const SECRET_KEY =  'supersecretkey';

const connectDB = async () => {
  try {
    await mongoose.connect(MONGO_URI);
    console.log('✅ Connected to MongoDB');
  } catch (err) {
    console.error('❌ MongoDB connection error:', err);
    process.exit(1);

  }
};
connectDB();

app.use(express.json());



const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Нет токена, доступ запрещён" });

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: "Неверный токен" });
  }
};
app.post('/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ name, email, password: hashedPassword });
    await newUser.save();
    res.status(201).json({ message: "Пользователь зарегистрирован" });
  } catch (err) {
    res.status(500).json({ error: "Ошибка регистрации" });
  }
});
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: "Неверные учетные данные" });
    }

    const token = jwt.sign({ id: user._id, email: user.email }, SECRET_KEY, { expiresIn: "1h" });
    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: "Ошибка авторизации" });
  }
});

app.get('/protected', authMiddleware, (req, res) => {
  res.json({ message: "Привет, ты авторизован!", user: req.user });
});

app.get('/read-file', authMiddleware, (req, res) => {
  const filePath = path.join(__dirname, 'data.txt');

  console.log('Before reading file...');

  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) {
      return res.status(500).json({ error: 'File read error' });
    }
    res.json({ content: data });
  });

  console.log('After initiating file read... (Event Loop is not blocked)');
});

app.listen(PORT, () => {
  console.log(`🚀 Server is running on port ${PORT}`);
});
