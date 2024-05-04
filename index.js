const express = require('express');
const axios = require('axios');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT;

app.use(express.json());

const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET;

// Verificar el token JWT
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

//Genera Token
const generateToken = (user) => {
  return jwt.sign(user, JWT_SECRET, { expiresIn: '1h' });
};

//app.post('/login', (req, res) => {
//const { username, password } = req.body;
//Lógica de user y pass
// if (username === 'raul' && password === '1234') {
//  const token = generateToken({ username });
//  res.json({ token }); //Devuelve token con 1h. de validez
//} else {
//  res.status(401).json({ error: 'Credenciales incorrectas' });
// }
//});

// Ruta para el login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const response = await axios.post('http://localhost:6002/login', {
      username,
      password
    });

    const { token } = response.data;
    res.json({ token });
  } catch (error) {
    console.error(error);
    res.status(401).json({ error: 'Credenciales incorrectas' });
  }
});

app.get('/sum', verifyToken, async (req, res) => {
  try {
    const { data: { num1, num2 } } = await axios.get('http://localhost:6001/random', {
      headers: {
        Authorization: req.headers.authorization // Pasar el token en la cabecera
      }
    });
    const suma = num1 + num2;
    res.json({ suma });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al sumar los números' });
  }
});

app.get('/registros', verifyToken, async (req, res) => {
  try {
    const response = await axios.get('http://localhost:6001/all_registers', {
      headers: {
        Authorization: req.headers.authorization // Pasar el token en la cabecera
      }
    });
    const registros = response.data;
    res.json({ registros });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener los registros' });
  }
});

app.put('/usuarios', verifyToken, async (req, res) => {
  try {
    const { username, password, nombre, apellido } = req.body;

    if (!username || !password || !nombre || !apellido) {
      return res.status(400).json({ error: 'Por favor, proporcione todos los campos requeridos' });
    }

    const response = await axios.put('http://localhost:6002/usuarios', req.body, {
      headers: {
        Authorization: req.headers.authorization // Pasar el token en la cabecera
      }
    });
    const usuarios = response.data;
    res.json({ usuarios });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al enviar los datos al microservicio de usuarios' });
  }
});

app.get('/usuarios', verifyToken, async (req, res) => {
  try {
    const response = await axios.get('http://localhost:6002/usuariosguardados', {
      headers: {
        Authorization: req.headers.authorization // Pasar el token en la cabecera
      }
    });
    const usuarios = response.data;
    res.json({ usuarios });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener los usuarios' });
  }
});

// Ruta para asignar roles a los usuarios
app.put('/usuarios/:id/roles', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { roles } = req.body;

    if (!roles || !Array.isArray(roles)) {
      return res.status(400).json({ error: 'Por favor, proporcione una lista de roles válida' });
    }

    const response = await axios.put(`http://localhost:6003/usuarios/${id}/roles`, { roles }, {
      headers: {
        Authorization: req.headers.authorization // Pasar el token en la cabecera
      }
    });

    const usuarios = response.data;
    res.json({ usuarios });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al asignar roles al usuario' });
  }
});

app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
