const express = require('express');
const bcrypt = require('bcrypt');
const session = require('express-session');
const { Pool } = require('pg');
const bodyParser = require('body-parser');
const path = require('path');
const dotenv = require('dotenv');
const ejs = require('ejs');
const pgSession = require('connect-pg-simple')(session);



dotenv.config();
const app = express();
const port = process.env.PORT || 3000;

// Устанавливаем EJS как шаблонизатор
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// База данных PostgreSQL
const pool = new Pool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT || 5432
});


// Проверка подключения к базе данных
pool.connect((err) => {
  if (err) {
    console.error('Ошибка подключения к базе данных:', err);
    throw err;
  }
  console.log('Connected to PostgreSQL database');
});

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

// Middleware
app.use(express.static(path.join(__dirname)));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(session({
  secret: 'hotel_secret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // Установите secure: true, если используете HTTPS
}));

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
  const { id } = req.params;
  try {
    const query = 'SELECT * FROM rooms WHERE id = $1';
    const result = await pool.query(query, [id]);
    if (result.rows.length === 0) {
      return res.status(404).send('Коттедж не найден');
    }
    res.render('room-details', { room: result.rows[0] });
  } catch (error) {
    console.error('Ошибка загрузки коттеджа:', error);
    res.status(500).send('Ошибка сервера');
  }
});

// Добавление в корзину
app.post('/cart/add', async (req, res) => {
  const { room_id, start_date, end_date, destination, transfer_date, transfer_time, type } = req.body;
  console.log('Получены данные для корзины:', req.body); // Отладка
  
  if (!req.session.cart) {
    req.session.cart = { rooms: [], transfers: [] };
    console.log('Создана новая корзина:', req.session.cart);
  }
  
  try {
    if (type === 'room') {
      if (!room_id || !start_date || !end_date) {
        console.error('Недостаточно данных для комнаты:', { room_id, start_date, end_date });
        return res.status(400).send('Заполните все поля для бронирования');
      }
      
      const roomQuery = 'SELECT number, price FROM rooms WHERE id = $1';
      const roomResult = await pool.query(roomQuery, [room_id]);
      if (roomResult.rows.length === 0) {
        console.error('Коттедж не найден:', room_id);
        return res.status(404).send('Коттедж не найден');
      }
      
      const startDate = new Date(start_date);
      const endDate = new Date(end_date);
      if (startDate >= endDate) {
        console.error('Неверные даты:', { start_date, end_date });
        return res.status(400).send('Дата выезда должна быть позже даты заезда');
      }
      
      const numberOfDays = Math.ceil((endDate - startDate) / (1000 * 3600 * 24));
      const totalCost = numberOfDays * roomResult.rows[0].price;
      
      req.session.cart.rooms.push({
        room_id,
        number: roomResult.rows[0].number,
        start_date,
        end_date,
        total_cost: totalCost
      });
      console.log('Добавлена комната в корзину:', req.session.cart.rooms);
    } else if (type === 'transfer') {
      if (!destination || !transfer_date || !transfer_time) {
        console.error('Недостаточно данных для трансфера:', { destination, transfer_date, transfer_time });
        return res.status(400).send('Заполните все поля для трансфера');
      }
      
      req.session.cart.transfers.push({
        destination,
        transfer_date,
        transfer_time
      });
      console.log('Добавлен трансфер в корзину:', req.session.cart.transfers);
    } else {
      console.error('Неизвестный или отсутствующий тип:', type);
      return res.status(400).send(`Неверный тип: ${type || 'отсутствует'}`);
    }
    
    await req.session.save(); // Явно сохраняем сессию
    console.log('Сессия сохранена:', req.session.cart);
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
    // Сохраняем брони
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
    }
    
    // Сохраняем трансферы
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

// Запуск сервера
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});