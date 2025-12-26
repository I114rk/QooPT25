require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const { GoogleGenerativeAI } = require("@google/generative-ai");

const app = express();
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
const STORAGE_PATH = path.join(__dirname, 'storage');

app.use(express.json());
app.use(cors());
app.use(express.static('public'));

if (!fs.existsSync(STORAGE_PATH)) fs.mkdirSync(STORAGE_PATH);

const db = new sqlite3.Database('./database.sqlite');

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_uuid TEXT UNIQUE,
        username TEXT UNIQUE,
        password TEXT
    )`);
});

// РЕГИСТРАЦИЯ
app.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        const { v4: uuidv4 } = await import('uuid');
        const user_uuid = uuidv4();
        const hashed = await bcrypt.hash(password, 10);

        db.run(`INSERT INTO users (user_uuid, username, password) VALUES (?, ?, ?)`, 
        [user_uuid, username, hashed], (err) => {
            if (err) return res.status(400).json({ error: "Пользователь уже существует" });
            
            const userDir = path.join(STORAGE_PATH, user_uuid);
            if (!fs.existsSync(userDir)) fs.mkdirSync(userDir);
            
            res.json({ success: true });
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// ВХОД
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
        if (err || !user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: "Неверный логин или пароль" });
        }
        const token = jwt.sign({ userId: user.id, userUuid: user.user_uuid }, process.env.JWT_SECRET);
        res.json({ token, username });
    });
});

// ПОЛУЧЕНИЕ СПИСКА ЧАТОВ (Тот самый недостающий кусок!)
app.get('/api/my-chats', (req, res) => {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) return res.sendStatus(403);
        
        const userDir = path.join(STORAGE_PATH, decoded.userUuid);
        if (!fs.existsSync(userDir)) return res.json([]);

        try {
            const files = fs.readdirSync(userDir);
            const allChats = files.filter(f => f.endsWith('.txt')).map(file => {
                const content = fs.readFileSync(path.join(userDir, file), 'utf8');
                const history = JSON.parse(content);
                const chatId = file.replace('history_', '').replace('.txt', '');
                
                return { 
                    id: chatId, 
                    title: history[0]?.parts[0]?.text.substring(0, 25) || "Старый чат", 
                    history 
                };
            });
            res.json(allChats.reverse());
        } catch (e) {
            res.json([]);
        }
    });
});

// ЧАТ
app.post('/api/chat', async (req, res) => {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
        if (err) return res.sendStatus(403);

        const { prompt, history, chatId } = req.body;
        const userUuid = decoded.userUuid;
        const userDir = path.join(STORAGE_PATH, userUuid);
        
        // На всякий случай создаем папку, если её нет
        if (!fs.existsSync(userDir)) fs.mkdirSync(userDir);

        const filePath = path.join(userDir, `history_${chatId}.txt`);

        try {
            const model = genAI.getGenerativeModel({ model: "gemini-2.5-flash" }); // 2.5 может быть недоступна, используй 1.5 для теста
            const chat = model.startChat({ history });
            const result = await chat.sendMessage(prompt);
            const response = await result.response;
            const aiText = response.text();

            const updatedHistory = [...history, 
                { role: "user", parts: [{ text: prompt }] },
                { role: "model", parts: [{ text: aiText }] }
            ];

            fs.writeFileSync(filePath, JSON.stringify(updatedHistory, null, 2), 'utf8');
            res.json({ text: aiText });
        } catch (error) {
            console.error(error);
            res.status(500).json({ error: error.message });
        }
    });
});

app.listen(process.env.PORT, () => console.log(`Сервер: http://localhost:${process.env.PORT}`));