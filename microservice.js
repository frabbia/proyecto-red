const express = require('express');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();
const PORT2 = process.env.PORT2;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

(async () => {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS generated_numbers (
        id SERIAL PRIMARY KEY,
        num1 INTEGER NOT NULL,
        num2 INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);
  } catch (err) {
    console.error('Error creando la tabla', err);
  } finally {
    client.release();
  }
})();

app.get('/random', async (req, res) => {
  const num1 = Math.floor(Math.random() * 9) + 1;
  const num2 = Math.floor(Math.random() * 9) + 1;
  const createdAt = new Date();

  try {
    const client = await pool.connect();
    await client.query('INSERT INTO generated_numbers (num1, num2, created_at) VALUES ($1, $2, $3)', [num1, num2, createdAt]);
    client.release();
    res.json({ num1, num2 });
  } catch (err) {
    console.error('Error en la ejecución de la query', err);
    res.status(500).json({ error: 'Error de servidor' });
  }
});


app.get('/all_registers', async (req, res) => {
  try {
    const client = await pool.connect();
    const result = await client.query('SELECT * FROM generated_numbers');
    client.release();
    res.json(result.rows);
  } catch (err) {
    console.error('Error al ejecutar la query', err);
    res.status(500).json({ error: 'Error al obtener los registros' });
  }
});

app.listen(PORT2, () => {
  console.log(`Servidor de números aleatorios corriendo en http://localhost:${PORT2}`);
});
