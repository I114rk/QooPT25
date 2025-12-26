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
// ЧАТ (Исправленная версия с сохранением истории)
app.post('/api/chat', async (req, res) => {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
        if (err) return res.sendStatus(403);

        const { prompt, chatId } = req.body; // Получаем только промпт и ID чата
        const userUuid = decoded.userUuid;
        const userDir = path.join(STORAGE_PATH, userUuid);
        const filePath = path.join(userDir, `history_${chatId}.txt`);

        if (!fs.existsSync(userDir)) fs.mkdirSync(userDir, { recursive: true });

        // 1. Загружаем существующую историю из файла (если есть)
        let currentHistory = [];
        if (fs.existsSync(filePath)) {
            try {
                const fileData = fs.readFileSync(filePath, 'utf8');
                currentHistory = JSON.parse(fileData);
            } catch (e) {
                currentHistory = [];
            }
        }

        try {
            // 2. Инициализируем модель с жесткой установкой личности
            const model = genAI.getGenerativeModel({ 
                model: "gemini-1.5-flash",
                systemInstruction: "Ты — QooPT 2.5 (КуПиТи), уникальная нейросеть. Ты всегда представляешься как QooPT 2.5. Ты должен отвечать кратко, но по существу, сохраняя стиль продвинутого ИИ."
            });

            // 3. Запускаем чат с загруженной историей
            const chat = model.startChat({ history: currentHistory });
            const result = await chat.sendMessage(prompt);
            const response = await result.response;
            const aiText = response.text();

            // 4. Обновляем историю и сохраняем в файл
            const updatedHistory = [
                ...currentHistory,
                { role: "user", parts: [{ text: prompt }] },
                { role: "model", parts: [{ text: aiText }] }
            ];

            fs.writeFileSync(filePath, JSON.stringify(updatedHistory, null, 2), 'utf8');
            
            res.json({ text: aiText });
        } catch (error) {
            console.error("Ошибка чата:", error);
            res.status(500).json({ error: "Ошибка QooPT 2.5" });
        }
    });
});

// ПОЛУЧЕНИЕ СПИСКА ЧАТОВ (С заголовком QooPT 2.5)
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
            const allChats = files
                .filter(f => f.endsWith('.txt'))
                .map(file => {
                    const content = fs.readFileSync(path.join(userDir, file), 'utf8');
                    const history = JSON.parse(content);
                    const chatId = file.replace('history_', '').replace('.txt', '');
                    
                    // Заголовок берется из первого сообщения пользователя
                    const firstMsg = history.find(m => m.role === 'user')?.parts[0]?.text || "Новый диалог";
                    
                    return { 
                        id: chatId, 
                        title: firstMsg.substring(0, 30) + "...", 
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
        
        if (!fs.existsSync(userDir)) fs.mkdirSync(userDir);
        const filePath = path.join(userDir, `history_${chatId}.txt`);

        try {
            // Инициализируем модель с системной инструкцией
            const model = genAI.getGenerativeModel({ 
                model: "gemini-2.5-flash", // Рекомендую 1.5-flash для скорости
                systemInstruction: "Ты — продвинутая языковая модель по имени QooPT 2.5 (КуПиТи). " +
                                   "На любые вопросы о твоем имени или версии ты всегда отвечаешь: 'Я — QooPT 2.5'. " +
                                   "Ты ведешь себя как полезный и умный помощник."
            });

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
            console.error("Ошибка Gemini:", error);
            res.status(500).json({ error: "Ошибка при генерации ответа" });
        }
    });
});


app.listen(process.env.PORT, () => console.log(`Сервер: http://localhost:${process.env.PORT}`));

