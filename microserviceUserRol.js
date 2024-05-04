const express = require('express');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const axios = require('axios');
require('dotenv').config();

const app = express();
const PORT4 = process.env.PORT4;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET;

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

(async () => {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS roles (
        id SERIAL PRIMARY KEY,
        nombre VARCHAR(50) UNIQUE NOT NULL,
        regular BOOLEAN NOT NULL
      )
    `);
    // Verificar si el rol ya existe antes de insertarlo
    await client.query(`INSERT INTO roles (nombre, regular) VALUES ('Admin', false) ON CONFLICT (nombre) DO NOTHING`);
    await client.query(`INSERT INTO roles (nombre, regular) VALUES ('Regular', true) ON CONFLICT (nombre) DO NOTHING`);
  } catch (err) {
    console.error('Error creando las tablas', err);
  } finally {
    client.release();
  }
})();

// Obtener todos los roles
app.get('/roles', async (req, res) => {
  try {
    const client = await pool.connect();
    const result = await client.query('SELECT * FROM roles');
    client.release();
    const roles = result.rows;
    res.json({ roles });
  } catch (error) {
    console.error('Error al obtener los roles', error);
    res.status(500).json({ error: 'Error al obtener los roles' });
  }
});

// Ruta para asignar roles a los usuarios
// Ruta para asignar roles a los usuarios
app.put('/usuarios/:id/roles', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { roles } = req.body;

    if (!roles || !Array.isArray(roles)) {
      return res.status(400).json({ error: 'Por favor, proporcione una lista de roles válida' });
    }

    const client = await pool.connect();
    await client.query('DELETE FROM usuarios_roles WHERE usuario_id = $1', [id]);

    const insertPromises = roles.map(async (role) => {
      await client.query('INSERT INTO usuarios_roles (usuario_id, rol) VALUES ($1, $2)', [id, role]);
    });

    await Promise.all(insertPromises);

    client.release();

    res.json({ message: 'Roles asignados correctamente' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al asignar roles al usuario' });
  }
});

app.listen(PORT4, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT4}`);
});
