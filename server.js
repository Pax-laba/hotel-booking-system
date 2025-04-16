const express = require('express');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const { Pool } = require('pg');
const bodyParser = require('body-parser');
const path = require('path');
const dotenv = require('dotenv');
const ejs = require('ejs');
const pgSession = require('connect-pg-simple')(session);

const cookieParser = require('cookie-parser');
const morgan = require('morgan');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');


dotenv.config();
const app = express();
const port = process.env.PORT || 3000;

// Устанавливаем EJS как шаблонизатор
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// База данных PostgreSQL
// const pool = new Pool({
//   host: process.env.DB_HOST,
//   user: process.env.DB_USER,
//   password: process.env.DB_PASSWORD,
//   database: process.env.DB_NAME,
//   port: process.env.DB_PORT || 5432
// });
// Подключение к PostgreSQL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: isProduction ? { rejectUnauthorized: false } : false
});

// Проверка подключения к базе данных
pool.connect((err) => {
  if (err) {
    console.error('Ошибка подключения к базе данных:', err);
    throw err;
  }
  console.log('Connected to PostgreSQL database');
});



// Middleware
app.use(cookieParser());
app.use(express.static(path.join(__dirname)));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(session({
  store: new pgSession({
    pool: pool, // Подключение к PostgreSQL
    tableName: 'session'
  }),
  secret: process.env.SESSION_SECRET || 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 } // 1 день
}));

// Логирование запросов
app.use(morgan('combined', {
  stream: fs.createWriteStream(path.join(__dirname, 'access.log'), { flags: 'a' })
}));

// Установка visitorId через cookies
app.use((req, res, next) => {
  if (!req.cookies.visitorId) {
    res.cookie('visitorId', uuidv4(), { maxAge: 365 * 24 * 60 * 60 * 1000 });
  }
  next();
});

// Запись просмотров страниц
app.use(async (req, res, next) => {
  try {
    if (req.cookies && req.cookies.visitorId) {
      await pool.query(
        'INSERT INTO page_views (visitor_id, page_url, view_date) VALUES ($1, $2, NOW())',
        [req.cookies.visitorId, req.originalUrl]
      );
    }
  } catch (error) {
    console.error('Ошибка записи просмотра:', error);
  }
  next();
});
// Middleware для проверки авторизации
const requireAuth = (req, res, next) => {
  if (!req.session.user) {
    return res.redirect('/');
  }
  next();
};

const requireAdmin = (req, res, next) => {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.redirect('/');
  }
  next();
};

// Главная страница
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Регистрация нового пользователя
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).send('Заполните все поля');
  }
  try {
    const checkEmailQuery = 'SELECT id FROM users WHERE email = $1';
    const emailResult = await pool.query(checkEmailQuery, [email]);
    if (emailResult.rows.length > 0) {
      return res.status(400).send('Email уже зарегистрирован');
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const query = 'INSERT INTO users (name, email, password, role) VALUES ($1, $2, $3, $4) RETURNING id';
    await pool.query(query, [name, email, hashedPassword, 'client']);
    res.redirect('/');
  } catch (error) {
    console.error('Ошибка при регистрации:', error);
    res.status(500).send('Ошибка при создании пользователя');
  }
});

// Вход в систему
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).send('Заполните все поля');
  }
  try {
    const query = 'SELECT * FROM users WHERE email = $1';
    const result = await pool.query(query, [email]);
    if (result.rows.length === 0) {
      return res.status(401).send('Неверный логин или пароль');
    }
    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).send('Неверный логин или пароль');
    }
    req.session.user = user;
    if (user.role === 'client') {
      res.redirect('/client-dashboard');
    } else {
      res.redirect('/admin-dashboard');
    }
  } catch (error) {
    console.error('Ошибка при входе:', error);
    res.status(500).send('Ошибка сервера');
  }
});

// Выход из системы
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Ошибка при выходе:', err);
      return res.status(500).send('Ошибка сервера');
    }
    res.redirect('/');
  });
});

// --- Бронирования ---

// Страница создания бронирования
app.get('/create-booking', requireAuth, async (req, res) => {
  try {
    const roomsQuery = 'SELECT id, number, price FROM rooms WHERE availability_status = $1 ORDER BY number';
    const roomsResult = await pool.query(roomsQuery, ['available']);
    res.render('create-booking', { rooms: roomsResult.rows, user: req.session.user });
  } catch (error) {
    console.error('Ошибка загрузки комнат:', error);
    res.status(500).send('Ошибка загрузки данных');
  }
});

// Создание нового бронирования
app.post('/create-booking', requireAuth, async (req, res) => {
  const { room_id, start_date, end_date } = req.body;
  const userId = req.session.user.id;
  if (!room_id || !start_date || !end_date) {
    return res.status(400).send('Заполните все поля');
  }
  try {
    // Проверяем только существование комнаты, без изменения статуса
    const roomQuery = 'SELECT price FROM rooms WHERE id = $1';
    const roomResult = await pool.query(roomQuery, [room_id]);
    if (roomResult.rows.length === 0) {
      return res.status(400).send('Комната не найдена');
    }
    const pricePerDay = roomResult.rows[0].price;
    const startDate = new Date(start_date);
    const endDate = new Date(end_date);
    if (startDate >= endDate) {
      return res.status(400).send('Дата окончания должна быть позже даты начала');
    }
    // Проверяем пересечение дат с активными бронированиями
    const overlapQuery = `
      SELECT id
      FROM bookings
      WHERE room_id = $1
      AND status IN ('reserved', 'confirmed')
      AND daterange(start_date, end_date, '[]') && daterange($2, $3, '[]')
    `;
    const overlapResult = await pool.query(overlapQuery, [room_id, start_date, end_date]);
    if (overlapResult.rows.length > 0) {
      return res.status(400).send('Коттедж занят на выбранные даты');
    }
    const numberOfDays = Math.ceil((endDate - startDate) / (1000 * 3600 * 24));
    const totalCost = numberOfDays * pricePerDay;
    const insertQuery = `
      INSERT INTO bookings (user_id, room_id, start_date, end_date, status, total_cost)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING id
    `;
    await pool.query(insertQuery, [userId, room_id, start_date, end_date, 'reserved', totalCost]);
    res.redirect('/client-dashboard');
  } catch (error) {
    console.error('Ошибка при создании бронирования:', error);
    res.status(500).send('Ошибка при создании бронирования: ' + error.message);
  }
});



// Получение всех бронирований (API для админа)
app.get('/bookings', requireAdmin, async (req, res) => {
  try {
    const query = `
      SELECT b.*, r.number AS room_number, u.name AS client_name
      FROM bookings b
      JOIN rooms r ON b.room_id = r.id
      JOIN users u ON b.user_id = u.id
    `;
    const result = await pool.query(query);
    res.status(200).json(result.rows);
  } catch (error) {
    console.error('Ошибка получения бронирований:', error);
    res.status(500).json({ message: 'Ошибка при получении бронирований' });
  }
});

// Отмена бронирования (клиент)
app.post('/client/cancel-booking/:id', requireAuth, async (req, res) => {
  const bookingId = req.params.id;
  try {
    const checkQuery = 'SELECT status, user_id FROM bookings WHERE id = $1';
    const checkResult = await pool.query(checkQuery, [bookingId]);
    if (checkResult.rows.length === 0) {
      return res.status(404).send('Бронирование не найдено');
    }
    if (checkResult.rows[0].user_id !== req.session.user.id && req.session.user.role !== 'admin') {
      return res.status(403).send('Нет доступа к этому бронированию');
    }
    if (checkResult.rows[0].status !== 'reserved') {
      return res.status(400).send('Бронирование нельзя отменить');
    }
    const query = 'UPDATE bookings SET status = $1 WHERE id = $2';
    await pool.query(query, ['cancelled', bookingId]);
    res.redirect('/view-bookings');
  } catch (error) {
    console.error('Ошибка при отмене бронирования:', error);
    res.status(500).send('Ошибка при отмене бронирования');
  }
});

// Подтверждение бронирования (админ)
app.post('/admin/confirm-booking', requireAdmin, async (req, res) => {
  const { bookingId } = req.body;
  if (!bookingId || isNaN(bookingId)) {
    return res.status(400).send('Неверный идентификатор бронирования');
  }
  try {
    const checkQuery = 'SELECT status FROM bookings WHERE id = $1';
    const checkResult = await pool.query(checkQuery, [bookingId]);
    if (checkResult.rows.length === 0) {
      return res.status(404).send('Бронирование не найдено');
    }
    if (checkResult.rows[0].status !== 'reserved') {
      return res.status(400).send('Бронирование нельзя подтвердить');
    }
    const query = 'UPDATE bookings SET status = $1 WHERE id = $2';
    await pool.query(query, ['confirmed', bookingId]);
    res.redirect('/admin-dashboard');
  } catch (error) {
    console.error('Ошибка подтверждения бронирования:', error);
    res.status(500).send('Ошибка при подтверждении бронирования');
  }
});

// Отмена бронирования (админ)
// Отмена бронирования администратором
app.post('/admin/cancel-booking', requireAdmin, async (req, res) => {
  const { bookingId } = req.body;
  try {
    const query = 'UPDATE bookings SET status = $1 WHERE id = $2 RETURNING *';
    const result = await pool.query(query, ['cancelled', bookingId]);
    if (result.rows.length === 0) {
      return res.status(404).send('Бронирование не найдено');
    }
    res.redirect('/admin-dashboard');
  } catch (error) {
    console.error('Ошибка отмены брони:', error);
    res.status(500).send('Ошибка сервера');
  }
});



// Закрытие коттеджа на даты (админ)
app.post('/admin/close-booking', requireAdmin, async (req, res) => {
  const { room_id, start_date, end_date } = req.body;
  if (!room_id || !start_date || !end_date) {
    return res.status(400).send('Заполните все поля');
  }
  try {
    const adminId = req.session.user.id; // Используем ID админа из сессии
    await pool.query('SELECT add_booking($1, $2, $3, $4, $5)', [adminId, room_id, start_date, end_date, 0]);
    await pool.query('UPDATE bookings SET status = $1 WHERE user_id = $2 AND room_id = $3 AND start_date = $4 AND end_date = $5', ['cancelled', adminId, room_id, start_date, end_date]);
    res.redirect('/admin-dashboard');
  } catch (error) {
    console.error('Ошибка закрытия коттеджа:', error);
    res.status(500).send('Ошибка при закрытии коттеджа: ' + error.message);
  }
});

// Получение недоступных дат
// Получение занятых дат для коттеджа
app.get('/get-unavailable-dates', async (req, res) => {
  const { room_id } = req.query;
  try {
    const query = `
      SELECT start_date, end_date + INTERVAL '1 day' as end_date
      FROM bookings
      WHERE room_id = $1 AND status IN ('reserved', 'confirmed')
    `;
    const result = await pool.query(query, [room_id]);
    const unavailableDates = result.rows.map(row => ({
      from: row.start_date.toISOString().split('T')[0],
      to: row.end_date.toISOString().split('T')[0]
    }));
    res.json({ unavailableDates });
  } catch (error) {
    console.error('Ошибка получения занятых дат:', error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// --- Трансферы ---

// Страница заказа трансфера
app.get('/order-transfer', requireAuth, (req, res) => {
  res.render('order-transfer', { user: req.session.user });
});

// Создание заявки на трансфер
app.post('/order-transfer', requireAuth, async (req, res) => {
  const { destination, transfer_date, transfer_time } = req.body;
  const userId = req.session.user.id;
  if (!destination || !transfer_date || !transfer_time) {
    return res.status(400).send('Заполните все поля');
  }
  try {
    const query = 'INSERT INTO transfers (user_id, destination, transfer_date, transfer_time, status) VALUES ($1, $2, $3, $4, $5) RETURNING id';
    await pool.query(query, [userId, destination, transfer_date, transfer_time, 'pending']);
    res.redirect('/client-dashboard');
  } catch (error) {
    console.error('Ошибка создания трансфера:', error);
    res.status(500).send('Ошибка при заказе трансфера');
  }
});

// Получение всех трансферов (API для админа)
app.get('/transfers', requireAdmin, async (req, res) => {
  try {
    const query = `
      SELECT t.*, u.name AS client_name
      FROM transfers t
      JOIN users u ON t.user_id = u.id
    `;
    const result = await pool.query(query);
    res.status(200).json(result.rows);
  } catch (error) {
    console.error('Ошибка получения трансферов:', error);
    res.status(500).json({ message: 'Ошибка при получении трансферов' });
  }
});

// Отмена трансфера (клиент)
app.post('/client/cancel-transfer/:id', requireAuth, async (req, res) => {
  const transferId = req.params.id;
  try {
    const checkQuery = 'SELECT status, user_id FROM transfers WHERE id = $1';
    const checkResult = await pool.query(checkQuery, [transferId]);
    if (checkResult.rows.length === 0) {
      return res.status(404).send('Трансфер не найден');
    }
    if (checkResult.rows[0].user_id !== req.session.user.id && req.session.user.role !== 'admin') {
      return res.status(403).send('Нет доступа к этому трансферу');
    }
    if (checkResult.rows[0].status !== 'pending') {
      return res.status(400).send('Трансфер нельзя отменить');
    }
    await pool.query('SELECT update_transfer_status($1, $2)', [transferId, 'cancelled']);
    res.redirect('/view-bookings');
  } catch (error) {
    console.error('Ошибка отмены трансфера:', error);
    res.status(500).send('Ошибка при отмене трансфера');
  }
});

// Подтверждение трансфера (админ)
app.post('/admin/confirm-transfer', requireAdmin, async (req, res) => {
  const { transferId } = req.body;
  if (!transferId || isNaN(transferId)) {
    return res.status(400).send('Неверный идентификатор трансфера');
  }
  try {
    const checkQuery = 'SELECT status FROM transfers WHERE id = $1';
    const checkResult = await pool.query(checkQuery, [transferId]);
    if (checkResult.rows.length === 0) {
      return res.status(404).send('Трансфер не найден');
    }
    if (checkResult.rows[0].status !== 'pending') {
      return res.status(400).send('Трансфер нельзя подтвердить');
    }
    await pool.query('SELECT update_transfer_status($1, $2)', [transferId, 'confirmed']);
    res.redirect('/admin-dashboard');
  } catch (error) {
    console.error('Ошибка подтверждения трансфера:', error);
    res.status(500).send('Ошибка при подтверждении трансфера');
  }
});

// Отмена трансфера (админ)
app.post('/admin/cancel-transfer', requireAdmin, async (req, res) => {
  const { transferId } = req.body;
  if (!transferId || isNaN(transferId)) {
    return res.status(400).send('Неверный идентификатор трансфера');
  }
  try {
    const checkQuery = 'SELECT status FROM transfers WHERE id = $1';
    const checkResult = await pool.query(checkQuery, [transferId]);
    if (checkResult.rows.length === 0) {
      return res.status(404).send('Трансфер не найден');
    }
    await pool.query('SELECT update_transfer_status($1, $2)', [transferId, 'cancelled']);
    res.redirect('/admin-dashboard');
  } catch (error) {
    console.error('Ошибка отмены трансфера:', error);
    res.status(500).send('Ошибка при отмене трансфера');
  }
});

// --- Услуги ---

// Страница заказа услуги
app.get('/order-service', requireAuth, async (req, res) => {
  try {
    const servicesQuery = 'SELECT id, name, price, description FROM services ORDER BY name';
    const bookingsQuery = 'SELECT id, room_id, start_date FROM bookings WHERE user_id = $1 AND status IN ($2, $3)';
    const servicesResult = await pool.query(servicesQuery);
    const bookingsResult = await pool.query(bookingsQuery, [req.session.user.id, 'reserved', 'confirmed']);
    res.render('order-service', {
      user: req.session.user,
      services: servicesResult.rows,
      bookings: bookingsResult.rows
    });
  } catch (error) {
    console.error('Ошибка загрузки услуг:', error);
    res.status(500).send('Ошибка загрузки данных');
  }
});

// Создание заказа услуги
app.post('/order-service', requireAuth, async (req, res) => {
  const { service_id, booking_id } = req.body;
  const userId = req.session.user.id;
  if (!service_id) {
    return res.status(400).send('Выберите услугу');
  }
  try {
    const serviceQuery = 'SELECT id FROM services WHERE id = $1';
    const serviceResult = await pool.query(serviceQuery, [service_id]);
    if (serviceResult.rows.length === 0) {
      return res.status(404).send('Услуга не найдена');
    }
    if (booking_id) {
      const bookingQuery = 'SELECT id FROM bookings WHERE id = $1 AND user_id = $2';
      const bookingResult = await pool.query(bookingQuery, [booking_id, userId]);
      if (bookingResult.rows.length === 0) {
        return res.status(404).send('Бронирование не найдено');
      }
    }
    const query = 'INSERT INTO service_orders (user_id, service_id, booking_id, status) VALUES ($1, $2, $3, $4)';
    await pool.query(query, [userId, service_id, booking_id || null, 'pending']);
    res.redirect('/client-dashboard');
  } catch (error) {
    console.error('Ошибка создания заказа услуги:', error);
    res.status(500).send('Ошибка при заказе услуги');
  }
});

// --- Отзывы ---

// Страница добавления отзыва
app.get('/add-review/:bookingId', requireAuth, async (req, res) => {
  const bookingId = req.params.bookingId;
  try {
    const bookingQuery = `
      SELECT b.*, r.number AS room_number
      FROM bookings b
      JOIN rooms r ON b.room_id = r.id
      WHERE b.id = $1 AND b.user_id = $2 AND b.status = $3
    `;
    const bookingResult = await pool.query(bookingQuery, [bookingId, req.session.user.id, 'confirmed']);
    if (bookingResult.rows.length === 0) {
      return res.status(404).send('Бронирование не найдено или недоступно для отзыва');
    }
    const reviewQuery = 'SELECT id FROM reviews WHERE booking_id = $1 AND user_id = $2';
    const reviewResult = await pool.query(reviewQuery, [bookingId, req.session.user.id]);
    if (reviewResult.rows.length > 0) {
      return res.status(400).send('Отзыв уже оставлен');
    }
    res.render('add-review', { booking: bookingResult.rows[0], user: req.session.user });
  } catch (error) {
    console.error('Ошибка загрузки бронирования:', error);
    res.status(500).send('Ошибка загрузки данных');
  }
});

// Создание отзыва
app.post('/add-review/:bookingId', requireAuth, async (req, res) => {
  const { rating, comment } = req.body;
  const bookingId = req.params.bookingId;
  const userId = req.session.user.id;
  if (!rating || rating < 1 || rating > 5) {
    return res.status(400).send('Укажите корректную оценку (1-5)');
  }
  try {
    const bookingQuery = 'SELECT id FROM bookings WHERE id = $1 AND user_id = $2 AND status = $3';
    const bookingResult = await pool.query(bookingQuery, [bookingId, userId, 'confirmed']);
    if (bookingResult.rows.length === 0) {
      return res.status(404).send('Бронирование не найдено или недоступно');
    }
    const reviewQuery = 'SELECT id FROM reviews WHERE booking_id = $1 AND user_id = $2';
    const reviewResult = await pool.query(reviewQuery, [bookingId, userId]);
    if (reviewResult.rows.length > 0) {
      return res.status(400).send('Отзыв уже оставлен');
    }
    const insertQuery = 'INSERT INTO reviews (user_id, booking_id, rating, comment) VALUES ($1, $2, $3, $4)';
    await pool.query(insertQuery, [userId, bookingId, rating, comment || null]);
    res.redirect('/view-bookings');
  } catch (error) {
    console.error('Ошибка создания отзыва:', error);
    res.status(500).send('Ошибка при добавлении отзыва');
  }
});

// --- Пользователи ---

// Получение всех пользователей (API для админа)
app.get('/users', requireAdmin, async (req, res) => {
  try {
    const query = 'SELECT id, name, email, role FROM users ORDER BY name';
    const result = await pool.query(query);
    res.status(200).json(result.rows);
  } catch (error) {
    console.error('Ошибка получения пользователей:', error);
    res.status(500).json({ message: 'Ошибка при получении пользователей' });
  }
});

// Страница редактирования пользователя
app.get('/admin/edit-user/:id', requireAdmin, async (req, res) => {
  const userId = req.params.id;
  try {
    const query = 'SELECT id, name, email, role FROM users WHERE id = $1';
    const result = await pool.query(query, [userId]);
    if (result.rows.length === 0) {
      return res.status(404).send('Пользователь не найден');
    }
    res.render('edit-user', { user: result.rows[0] });
  } catch (error) {
    console.error('Ошибка получения пользователя:', error);
    res.status(500).send('Ошибка загрузки данных пользователя');
  }
});

// Обновление пользователя (админ)
app.post('/admin/update-user/:id', requireAdmin, async (req, res) => {
  const userId = req.params.id;
  const { name, email, role } = req.body;
  if (!name || !email || !role) {
    return res.status(400).send('Заполните все поля');
  }
  try {
    const checkEmailQuery = 'SELECT id FROM users WHERE email = $1 AND id != $2';
    const emailResult = await pool.query(checkEmailQuery, [email, userId]);
    if (emailResult.rows.length > 0) {
      return res.status(400).send('Email уже используется');
    }
    const query = 'UPDATE users SET name = $1, email = $2, role = $3 WHERE id = $4';
    await pool.query(query, [name, email, role, userId]);
    res.redirect('/admin-dashboard');
  } catch (error) {
    console.error('Ошибка обновления пользователя:', error);
    res.status(500).send('Ошибка при обновлении данных пользователя');
  }
});

// Удаление пользователя (админ)
app.post('/admin/delete-user/:id', requireAdmin, async (req, res) => {
  const userId = req.params.id;
  if (userId == req.session.user.id) {
    return res.status(400).send('Нельзя удалить самого себя');
  }
  try {
    const query = 'DELETE FROM users WHERE id = $1';
    await pool.query(query, [userId]);
    res.redirect('/admin-dashboard');
  } catch (error) {
    console.error('Ошибка удаления пользователя:', error);
    res.status(500).send('Ошибка при удалении пользователя');
  }
});

// --- Панели и просмотр ---

// Панель клиента
app.get('/client-dashboard', requireAuth, async (req, res) => {
  try {
    const bookingsQuery = `
      SELECT b.*, r.number AS room_number
      FROM bookings b
      JOIN rooms r ON b.room_id = r.id
      WHERE b.user_id = $1
      ORDER BY b.start_date DESC
      LIMIT 5
    `;
    const transfersQuery = 'SELECT * FROM transfers WHERE user_id = $1 ORDER BY transfer_date DESC LIMIT 5';
    const bookingsResult = await pool.query(bookingsQuery, [req.session.user.id]);
    const transfersResult = await pool.query(transfersQuery, [req.session.user.id]);
    res.render('client-dashboard', {
      user: req.session.user,
      bookings: bookingsResult.rows,
      transfers: transfersResult.rows
    });
  } catch (error) {
    console.error('Ошибка загрузки клиентской панели:', error);
    res.status(500).send('Ошибка загрузки данных');
  }
});

// Просмотр истории бронирований и трансферов
// История бронирований клиента
app.get('/view-bookings', requireAuth, async (req, res) => {
  try {
    const bookingsQuery = `
      SELECT b.id, b.start_date, b.end_date, b.status, r.number AS room_number, b.total_cost
      FROM bookings b
      JOIN rooms r ON b.room_id = r.id
      WHERE b.user_id = $1
      ORDER BY b.start_date DESC
    `;
    const transfersQuery = `
      SELECT id, destination, transfer_date, transfer_time, status
      FROM transfers
      WHERE user_id = $1
      ORDER BY transfer_date DESC
    `;
    const serviceOrdersQuery = `
      SELECT so.id, s.name AS service_name, so.order_date, so.status, so.booking_id
      FROM service_orders so
      JOIN services s ON so.service_id = s.id
      WHERE so.user_id = $1
      ORDER BY so.order_date DESC
    `;
    const reviewsQuery = `
      SELECT r.id, r.rating, r.comment, r.created_at, rm.number AS room_number
      FROM reviews r
      JOIN bookings b ON r.booking_id = b.id
      JOIN rooms rm ON b.room_id = rm.id
      WHERE r.user_id = $1
      ORDER BY r.created_at DESC
    `;
    const bookingsResult = await pool.query(bookingsQuery, [req.session.user.id]);
    const transfersResult = await pool.query(transfersQuery, [req.session.user.id]);
    const serviceOrdersResult = await pool.query(serviceOrdersQuery, [req.session.user.id]);
    const reviewsResult = await pool.query(reviewsQuery, [req.session.user.id]);
    res.render('view-bookings', {
      bookings: bookingsResult.rows,
      transfers: transfersResult.rows,
      serviceOrders: serviceOrdersResult.rows,
      reviews: reviewsResult.rows
    });
  } catch (error) {
    console.error('Ошибка загрузки истории бронирований:', error);
    res.status(500).send('Ошибка сервера');
  }
});

// Панель администратора
app.get('/admin-dashboard', requireAdmin, async (req, res) => {
  const clientName = req.query.client_name || '';
  try {
    const bookingsQuery = `
      SELECT b.id, r.number AS room_number, b.start_date, b.end_date, b.status, 
             u.name AS client_name, u.email AS client_email,
             r.price AS price_per_day,
             (b.end_date - b.start_date) AS number_of_days,
             b.total_cost
      FROM bookings b
      JOIN users u ON b.user_id = u.id
      JOIN rooms r ON b.room_id = r.id
      WHERE u.name ILIKE $1
      ORDER BY b.start_date DESC
    `;
    const transfersQuery = `
      SELECT t.id, t.destination, t.transfer_date, t.transfer_time, t.status,
             u.name AS client_name, u.email AS client_email 
      FROM transfers t
      JOIN users u ON t.user_id = u.id
      ORDER BY t.transfer_date DESC, t.transfer_time DESC
    `;
    const usersQuery = 'SELECT id, name, email, role FROM users ORDER BY name';
    const roomsQuery = 'SELECT id, number, price FROM rooms ORDER BY number';
    const servicesQuery = 'SELECT id, name, price, description FROM services ORDER BY name';
    const serviceOrdersQuery = `
      SELECT so.id, s.name AS service_name, u.name AS client_name, so.status, so.order_date,
             b.id AS booking_id
      FROM service_orders so
      JOIN services s ON so.service_id = s.id
      JOIN users u ON so.user_id = u.id
      LEFT JOIN bookings b ON so.booking_id = b.id
      ORDER BY so.order_date DESC
    `;
    const reviewsQuery = `
      SELECT rv.id, rv.rating, rv.comment, rv.created_at,
             u.name AS client_name, r.number AS room_number
      FROM reviews rv
      JOIN bookings b ON rv.booking_id = b.id
      JOIN users u ON rv.user_id = u.id
      JOIN rooms r ON b.room_id = r.id
      ORDER BY rv.created_at DESC
    `;
    const bookingsResult = await pool.query(bookingsQuery, [`%${clientName}%`]);
    const transfersResult = await pool.query(transfersQuery);
    const usersResult = await pool.query(usersQuery);
    const roomsResult = await pool.query(roomsQuery);
    const servicesResult = await pool.query(servicesQuery);
    const serviceOrdersResult = await pool.query(serviceOrdersQuery);
    const reviewsResult = await pool.query(reviewsQuery);
    res.render('admin-dashboard', {
      user: req.session.user,
      bookings: bookingsResult.rows,
      transfers: transfersResult.rows,
      users: usersResult.rows,
      rooms: roomsResult.rows,
      services: servicesResult.rows,
      serviceOrders: serviceOrdersResult.rows,
      reviews: reviewsResult.rows,
      clientName
    });
  } catch (error) {
    console.error('Ошибка загрузки админ-панели:', error);
    res.status(500).send('Ошибка загрузки данных');
  }
});


// Каталог коттеджей
app.get('/catalog', async (req, res) => {
  const { search, sort, max_guests } = req.query;
  let query = 'SELECT * FROM rooms WHERE availability_status = $1';
  const params = ['available'];
  
  // Поиск по названию
  if (search) {
    query += ' AND number ILIKE $' + (params.length + 1);
    params.push(`%${search}%`);
  }
  
  // Фильтрация по количеству гостей
  if (max_guests) {
    query += ' AND max_guests >= $' + (params.length + 1);
    params.push(parseInt(max_guests));
  }
  
  // Сортировка
  if (sort === 'price_asc') {
    query += ' ORDER BY price ASC';
  } else if (sort === 'price_desc') {
    query += ' ORDER BY price DESC';
  } else {
    query += ' ORDER BY number';
  }
  
  try {
    const result = await pool.query(query, params);
    res.render('catalog', {
      rooms: result.rows,
      search: search || '',
      max_guests: max_guests || '',
      sort: sort || ''
    });
  } catch (error) {
    console.error('Ошибка загрузки каталога:', error);
    res.status(500).send('Ошибка сервера');
  }
});

// Информация о коттедже
app.get('/room/:id', async (req, res) => {
  try {
    const roomResult = await pool.query('SELECT * FROM rooms WHERE id = $1', [req.params.id]);
    if (roomResult.rows.length === 0) {
      return res.status(404).send('Коттедж не найден');
    }
    if (req.session.user) {
      await pool.query(
        'INSERT INTO sales_metrics (room_id, action, user_id, created_at) VALUES ($1, $2, $3, NOW())',
        [req.params.id, 'view', req.session.user.id]
      );
    }
    res.render('room-details', { room: roomResult.rows[0] });
  } catch (error) {
    console.error('Ошибка загрузки коттеджа:', error);
    res.status(500).send('Ошибка сервера');
  }
});

// Добавление в корзину
app.post('/cart/add', requireAuth, async (req, res) => {
  const { room_id, start_date, end_date, type, destination, transfer_date, transfer_time } = req.body;
  let cart = req.session.cart || { rooms: [], transfers: [] };
  try {
    if (type === 'room') {
      const roomResult = await pool.query('SELECT * FROM rooms WHERE id = $1', [room_id]);
      if (roomResult.rows.length === 0) {
        return res.status(404).send('Коттедж не найден');
      }
      const room = roomResult.rows[0];
      const start = new Date(start_date);
      const end = new Date(end_date);
      const days = (end - start) / (1000 * 60 * 60 * 24);
      const total_cost = room.price * days;
      cart.rooms.push({
        room_id,
        number: room.number,
        start_date,
        end_date,
        total_cost
      });
      await pool.query(
        'INSERT INTO sales_metrics (room_id, action, user_id, created_at) VALUES ($1, $2, $3, NOW())',
        [room_id, 'add_to_cart', req.session.user.id]
      );
    } else if (type === 'transfer') {
      cart.transfers.push({ destination, transfer_date, transfer_time });
    }
    req.session.cart = cart;
    await req.session.save();
    res.redirect('/cart');
  } catch (error) {
    console.error('Ошибка добавления в корзину:', error);
    res.status(500).send('Ошибка сервера');
  }
});

// Отображение корзины
app.get('/cart', (req, res) => {
  const cart = req.session.cart || { rooms: [], transfers: [] };
  console.log('Отображение корзины:', cart); // Отладка
  res.render('cart', { cart });
});

// Удаление из корзины
app.post('/cart/remove', (req, res) => {
  const { index, type } = req.body;
  if (!req.session.cart) return res.redirect('/cart');
  
  if (type === 'room') {
    req.session.cart.rooms.splice(index, 1);
  } else if (type === 'transfer') {
    req.session.cart.transfers.splice(index, 1);
  }
  res.redirect('/cart');
});

// Оформление заказа
app.get('/checkout', requireAuth, (req, res) => {
  const cart = req.session.cart || { rooms: [], transfers: [] };
  res.render('checkout', { cart, user: req.session.user });
});

app.post('/checkout', requireAuth, async (req, res) => {
  const cart = req.session.cart || { rooms: [], transfers: [] };
  const userId = req.session.user.id;
  try {
    for (const room of cart.rooms) {
      const overlapQuery = `
        SELECT id
        FROM bookings
        WHERE room_id = $1
        AND status IN ('reserved', 'confirmed')
        AND (
          (start_date <= $2 AND end_date >= $2) OR
          (start_date <= $3 AND end_date >= $3) OR
          (start_date >= $2 AND end_date <= $3)
        )
      `;
      const overlapResult = await pool.query(overlapQuery, [room.room_id, room.start_date, room.end_date]);
      if (overlapResult.rows.length > 0) {
        return res.status(400).send('Коттедж занят на выбранные даты');
      }
      await pool.query(
        'INSERT INTO bookings (user_id, room_id, start_date, end_date, status, total_cost) VALUES ($1, $2, $3, $4, $5, $6)',
        [userId, room.room_id, room.start_date, room.end_date, 'reserved', room.total_cost]
      );
      await pool.query(
        'INSERT INTO sales_metrics (room_id, action, user_id, created_at) VALUES ($1, $2, $3, NOW())',
        [room.room_id, 'purchase', userId]
      );
    }
    for (const transfer of cart.transfers) {
      await pool.query(
        'INSERT INTO transfers (user_id, destination, transfer_date, transfer_time, status) VALUES ($1, $2, $3, $4, $5)',
        [userId, transfer.destination, transfer.transfer_date, transfer.transfer_time, 'pending']
      );
    }
    // Очищаем корзину
    req.session.cart = { rooms: [], transfers: [] };
    await req.session.save();
    res.redirect('/view-bookings');
  } catch (error) {
    console.error('Ошибка оформления заказа:', error);
    res.status(500).send('Ошибка сервера');
  }
});


// Маршрут для личного кабинета
// Маршрут для личного кабинета
app.get('/profile', requireAuth, async (req, res) => {
  try {
    res.render('profile', {
      user: req.session.user,
      error: null
    });
  } catch (error) {
    console.error('Ошибка загрузки профиля:', error);
    res.status(500).send('Ошибка сервера');
  }
});

// Маршрут для редактирования профиля
app.post('/profile', requireAuth, async (req, res) => {
  const { name, email, phone, address, old_password, password } = req.body;
  try {
    // Проверка email на уникальность
    const emailCheck = await pool.query('SELECT id FROM users WHERE email = $1 AND id != $2', [email, req.session.user.id]);
    if (emailCheck.rows.length > 0) {
      return res.render('profile', {
        user: req.session.user,
        error: 'Email уже используется'
      });
    }

    // Если указан новый пароль, проверяем старый
    if (password) {
      if (!old_password) {
        return res.render('profile', {
          user: req.session.user,
          error: 'Введите текущий пароль для смены пароля'
        });
      }
      const userQuery = await pool.query('SELECT password FROM users WHERE id = $1', [req.session.user.id]);
      const isMatch = await bcrypt.compare(old_password, userQuery.rows[0].password);
      if (!isMatch) {
        return res.render('profile', {
          user: req.session.user,
          error: 'Неверный текущий пароль'
        });
      }
    }

    // Обновление профиля
    let query = 'UPDATE users SET name = $1, email = $2, phone = $3, address = $4, updated_at = NOW()';
    const params = [name, email, phone || null, address || null, req.session.user.id];
    if (password) {
      const hashedPassword = await bcrypt.hash(password, 10);
      query += ', password = $5 WHERE id = $6';
      params.splice(4, 0, hashedPassword);
    } else {
      query += ' WHERE id = $5';
    }
    await pool.query(query, params);

    // Обновление сессии
    req.session.user = { ...req.session.user, name, email, phone, address };
    await req.session.save();

    res.redirect('/profile');
  } catch (error) {
    console.error('Ошибка обновления профиля:', error);
    res.render('profile', {
      user: req.session.user,
      error: 'Ошибка сервера'
    });
  }
});

// Маршрут для статистики продаж
app.get('/sales-statistics', requireAdmin, async (req, res) => {
  const { start_date, end_date, type } = req.query;
  try {
    let bookingsQuery = `
      SELECT r.number AS room_number, COUNT(b.id) AS bookings_count, COALESCE(SUM(b.total_cost), 0) AS total_revenue
      FROM bookings b
      JOIN rooms r ON b.room_id = r.id
      WHERE b.status IN ('reserved', 'confirmed')
    `;
    let transfersQuery = `
      SELECT destination, COUNT(id) AS transfers_count
      FROM transfers
      WHERE status = 'confirmed'
    `;
    const paramsBookings = [];
    const paramsTransfers = [];
    if (start_date) {
      bookingsQuery += ` AND b.start_date >= $1`;
      transfersQuery += ` AND transfer_date >= $1`;
      paramsBookings.push(start_date);
      paramsTransfers.push(start_date);
    }
    if (end_date) {
      const endIndex = paramsBookings.length + 1;
      bookingsQuery += ` AND b.end_date <= $${endIndex}`;
      transfersQuery += ` AND transfer_date <= $${endIndex}`;
      paramsBookings.push(end_date);
      paramsTransfers.push(end_date);
    }
    bookingsQuery += ` GROUP BY r.number`;
    transfersQuery += ` GROUP BY destination`;
    const bookingsResult = type === 'transfers' ? { rows: [] } : await pool.query(bookingsQuery, paramsBookings);
    const transfersResult = type === 'bookings' ? { rows: [] } : await pool.query(transfersQuery, paramsTransfers);
    res.render('sales-statistics', {
      bookings: bookingsResult.rows,
      transfers: transfersResult.rows,
      start_date: start_date || '',
      end_date: end_date || '',
      type: type || ''
    });
  } catch (error) {
    console.error('Ошибка статистики:', error);
    res.status(500).send('Ошибка сервера');
  }
});

// Маршрут для статистики посещений
app.get('/visit-statistics', requireAdmin, async (req, res) => {
  try {
    const pageViews = await pool.query(`
      SELECT page_url, COUNT(*) AS view_count
      FROM page_views
      GROUP BY page_url
      ORDER BY view_count DESC
    `);
    const salesActions = await pool.query(`
      SELECT r.number AS room_number, m.action, COUNT(*) AS action_count
      FROM sales_metrics m
      JOIN rooms r ON m.room_id = r.id
      GROUP BY r.number, m.action
      ORDER BY r.number, m.action
    `);
    res.render('visit-statistics', {
      pageViews: pageViews.rows,
      salesActions: salesActions.rows
    });
  } catch (error) {
    console.error('Ошибка статистики посещений:', error);
    res.status(500).send('Ошибка сервера');
  }
});

//Чат-бот 
const http = require('http');
const WebSocket = require('ws');
const cookie = require('cookie');

// Создаем HTTP-сервер на основе Express
const server = http.createServer(app);
const wss = new WebSocket.Server({ server }); // Привязываем WebSocket к серверу Express

wss.on('connection', (ws, req) => {
  const cookies = cookie.parse(req.headers.cookie || '');
  const sessionId = cookies['connect.sid']?.replace(/^s:/, '').split('.')[0] || '';

  ws.on('message', async (data) => {
    try {
      const msg = JSON.parse(data);
      const userMessage = msg.message.toLowerCase().trim();

      // Получение сессии
      const sessionQuery = await pool.query(
        'SELECT sess FROM session WHERE sid = $1 AND sess->\'user\' IS NOT NULL',
        [sessionId]
      );
      const user = sessionQuery.rows[0]?.sess?.user;

      if (!user) {
        ws.send(JSON.stringify({ message: 'Похоже, ты не вошел в аккаунт. Попробуй войти снова!' }));
        return;
      }

      if (userMessage === 'init') {
        const roomsQuery = await pool.query(
          'SELECT id, number FROM rooms WHERE availability_status = $1 ORDER BY number',
          ['available']
        );
        ws.send(JSON.stringify({ rooms: roomsQuery.rows }));
      } else if (userMessage.includes('поиск')) {
        const searchTerm = userMessage.replace('поиск', '').trim();
        let query = 'SELECT id, number, max_guests, price, image_url FROM rooms WHERE availability_status = $1';
        const params = ['available'];
        if (searchTerm) {
          query += ' AND (number ILIKE $2 OR max_guests::text ILIKE $2)';
          params.push(`%${searchTerm}%`);
        }
        query += ' ORDER BY number';
        const result = await pool.query(query, params);
        ws.send(JSON.stringify(
          result.rows.length === 0
            ? { message: 'Свободных коттеджей не найдено. Попробуй позже!' }
            : { cottages: result.rows }
        ));
      } else if (userMessage.includes('подробно')) {
        const cottageId = userMessage.replace('подробно', '').trim();
        if (!cottageId.match(/^\d+$/)) {
          ws.send(JSON.stringify({ message: 'ID коттеджа должен быть числом, например: 1' }));
          return;
        }
        const cottageQuery = await pool.query(
          'SELECT id, number, max_guests, price, availability_status, image_url FROM rooms WHERE id = $1',
          [cottageId]
        );
        ws.send(JSON.stringify(
          cottageQuery.rows.length === 0
            ? { message: 'Такого коттеджа нет. Напиши другой ID!' }
            : { cottage: cottageQuery.rows[0] }
        ));
      } else if (userMessage.includes('get-dates')) {
        const roomId = userMessage.replace('get-dates', '').trim();
        if (!roomId.match(/^\d+$/)) {
          ws.send(JSON.stringify({ message: 'ID коттеджа должен быть числом!' }));
          return;
        }
        const bookingsQuery = await pool.query(
          'SELECT start_date, end_date FROM bookings WHERE room_id = $1 AND status IN ($2, $3)',
          [roomId, 'reserved', 'confirmed']
        );
        const unavailableDates = bookingsQuery.rows.map(b => ({
          from: b.start_date,
          to: b.end_date
        }));
        ws.send(JSON.stringify({ unavailableDates }));
      } else if (userMessage.includes('заказ')) {
        const match = userMessage.match(/заказ\s+(\d+)\s+(\d{4}-\d{2}-\d{2})\s+(\d{4}-\d{2}-\d{2})/);
        if (!match) {
          ws.send(JSON.stringify({ 
            message: 'Напиши команду правильно, например: заказ 1 2025-05-01 2025-05-05' 
          }));
          return;
        }
        const [, roomId, startDate, endDate] = match;
        const roomQuery = await pool.query(
          'SELECT price, availability_status, number FROM rooms WHERE id = $1',
          [roomId]
        );
        if (roomQuery.rows.length === 0 || roomQuery.rows[0].availability_status !== 'available') {
          ws.send(JSON.stringify({ message: 'Этот коттедж недоступен. Выбери другой!' }));
          return;
        }
        const overlapQuery = `
          SELECT id FROM bookings
          WHERE room_id = $1 AND status IN ('reserved', 'confirmed')
          AND daterange(start_date, end_date, '[]') && daterange($2, $3, '[]')
        `;
        const overlapResult = await pool.query(overlapQuery, [roomId, startDate, endDate]);
        if (overlapResult.rows.length > 0) {
          ws.send(JSON.stringify({ message: 'Эти даты заняты. Выбери другие даты!' }));
          return;
        }
        const start = new Date(startDate);
        const end = new Date(endDate);
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        if (start < today) {
          ws.send(JSON.stringify({ message: 'Нельзя бронировать прошлые даты. Выбери даты с сегодняшнего дня!' }));
          return;
        }
        if (end <= start) {
          ws.send(JSON.stringify({ message: 'Дата отъезда должна быть позже даты приезда!' }));
          return;
        }
        const price = roomQuery.rows[0].price;
        const roomNumber = roomQuery.rows[0].number;
        const days = Math.ceil((end - start) / (1000 * 3600 * 24));
        const totalCost = days * price;
        await pool.query(
          'INSERT INTO bookings (user_id, room_id, start_date, end_date, status, total_cost) VALUES ($1, $2, $3, $4, $5, $6)',
          [user.id, roomId, startDate, endDate, 'reserved', totalCost]
        );
        ws.send(JSON.stringify({ 
          message: `Готово! Ты забронировал "${roomNumber}" (ID: ${roomId}) с ${new Date(startDate).toLocaleDateString('ru-RU')} по ${new Date(endDate).toLocaleDateString('ru-RU')}. Стоимость: ${totalCost} руб.` 
        }));
      } else if (userMessage.includes('история')) {
        const bookingsQuery = `
          SELECT b.*, r.number AS room_number
          FROM bookings b JOIN rooms r ON b.room_id = r.id
          WHERE b.user_id = $1 ORDER BY b.start_date DESC LIMIT 5
        `;
        const transfersQuery = `
          SELECT * FROM transfers
          WHERE user_id = $1 ORDER BY transfer_date DESC LIMIT 5
        `;
        const bookings = await pool.query(bookingsQuery, [user.id]);
        const transfers = await pool.query(transfersQuery, [user.id]);
        const history = [
          ...bookings.rows.map(b => ({
            type: 'booking',
            room_number: b.room_number,
            start_date: b.start_date,
            end_date: b.end_date,
            total_cost: b.total_cost,
            status: b.status
          })),
          ...transfers.rows.map(t => ({
            type: 'transfer',
            destination: t.destination,
            transfer_date: t.transfer_date,
            transfer_time: t.transfer_time,
            status: t.status
          }))
        ];
        ws.send(JSON.stringify({ history }));
      } else {
        ws.send(JSON.stringify({ 
          message: 'Не понял команду. Попробуй кнопки: "Найти коттеджи", "Забронировать" или "Мои заказы"!' 
        }));
      }
    } catch (error) {
      console.error('Ошибка чат-бота:', error);
      ws.send(JSON.stringify({ message: 'Ой, что-то пошло не так! Попробуй снова через пару секунд.' }));
    }
  });
});
// Запуск сервера
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});