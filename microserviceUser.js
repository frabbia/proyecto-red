const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const axios = require('axios');

const app = express();
const PORT3 = process.env.PORT3;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET;
const ROLE_SERVICE_URL = process.env.ROLE_SERVICE_URL;

// Middleware para verificar el token JWT
const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token no proporcionado' });
  }

  const token = authHeader.split(' ')[1];

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: 'Token inválido' });
    }
    req.user = decoded;
    next();
  });
};

// Generar Token
const generateToken = (user) => {
  return jwt.sign(user, JWT_SECRET, { expiresIn: '1h' });
};

// Ruta para el login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const client = await pool.connect();
    const result = await client.query('SELECT * FROM usuarios WHERE username = $1', [username]);
    const user = result.rows[0];
    client.release();

    if (!user) {
      return res.status(401).json({ error: 'Usuario no encontrado' });
    }

    const validPassword = await bcrypt.compare(password, user.pass);
    if (!validPassword) {
      return res.status(401).json({ error: 'Credenciales incorrectas' });
    }

    const token = generateToken({ username: user.username, rol: user.rol }); // Generar token

    res.json({ token }); // Devolver token
  } catch (error) {
    console.error('Error en la autenticación', error);
    res.status(500).json({ error: 'Error en la autenticación' });
  }
});

// Registrar usuario
app.put('/usuarios', verifyToken, async (req, res) => {
  const { username, password, nombre, apellido } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10); // Encriptar la contraseña antes de guardarla en la base de datos

    const client = await pool.connect();
    const result = await client.query('INSERT INTO usuarios (username, pass, nombre, apellido) VALUES ($1, $2, $3, $4) RETURNING *', [username, hashedPassword, nombre, apellido]);
    client.release();
    const newUser = result.rows[0];

    res.json(newUser);
  } catch (error) {
    console.error('Error al registrar el usuario', error);
    res.status(500).json({ error: 'Error al registrar el usuario' });
  }
});

// Obtener todos los usuarios
app.get('/usuariosguardados', verifyToken, async (req, res) => {
  try {
    const client = await pool.connect();
    const result = await client.query('SELECT * FROM usuarios');
    client.release();
    const usuarios = result.rows;
    res.json({ usuarios });
  } catch (error) {
    console.error('Error al obtener los usuarios', error);
    res.status(500).json({ error: 'Error al obtener los usuarios' });
  }
});

app.listen(PORT3, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT3}`);
});
