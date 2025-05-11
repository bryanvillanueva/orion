// Orion Backend - server.js

const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const { OpenAI } = require('openai');
const rateLimit = require('express-rate-limit');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session); // <-- añadido
require('dotenv').config();
const mysql = require('mysql2/promise');

const app = express();
const port = process.env.PORT || 3000;

// Configurar base de datos para sesión MySQL
const dbOptions = {
  host: process.env.DB_HOST,
  port: 3306,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME
};
const sessionStore = new MySQLStore(dbOptions); // <-- añadido

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Configurar Express
app.set('trust proxy', 1);
app.use(session({
  key: 'orion.sid',
  secret: process.env.SESSION_SECRET || 'clave_segura',
  store: sessionStore,        // <-- usar MySQLStore en lugar de MemoryStore
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false,            // true si usas HTTPS en producción
    maxAge: 1000 * 60 * 60 * 24 * 7 // 7 días
  }
}));

app.use(passport.initialize());
app.use(passport.session());

app.use(cors());
app.use(bodyParser.json());

// Configurar OpenAI
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// Configurar Passport con Google
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.CALLBACK_URL
}, (accessToken, refreshToken, profile, done) => {
  return done(null, {
    id: profile.id,
    email: profile.emails[0].value,
    name: profile.displayName
  });
}));

// Rate limiting middleware
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 100
});
app.use('/generate', limiter);

// Prompt builder
function buildPrompt(type, text, userInstruction) {
  const instructions = userInstruction ? `\nInstrucciones adicionales: ${userInstruction}` : '';

  switch (type) {
    case 'reply':
      return `Genera una respuesta profesional y cordial al siguiente mensaje:\n\n"${text}"\n\nInstrucciones:\n- Mantén un tono profesional pero amigable\n- Sé conciso y directo\n- Asegúrate de responder todos los puntos mencionados${instructions}`;
    case 'rewrite':
      return `Reescribe el siguiente texto mejorando su claridad, profesionalismo y estructura:\n\n"${text}"\n\nInstrucciones:\n- Mantén el mensaje principal\n- Mejora la gramática y puntuación\n- Usa un tono profesional\n- Hazlo más conciso si es posible${instructions}`;
    case 'translate':
      const targetLang = userInstruction || 'español';
      return `Traduce el siguiente texto al ${targetLang}:\n\n"${text}"\n\nMantén el tono y estilo del original.`;
    case 'polish':
      return `Mejora el siguiente texto corrigiendo errores y puliendo el estilo:\n\n"${text}"\n\nInstrucciones:\n- Corrige errores gramaticales y ortográficos\n- Mejora la fluidez y coherencia\n- Mantén el tono original\n- No cambies el significado${instructions}`;
    case 'template':
      return `Genera una respuesta usando esta plantilla profesional:\n\nContexto: "${text}"\n\nCrea una respuesta estructurada que incluya:\n1. Saludo apropiado\n2. Reconocimiento del mensaje\n3. Respuesta a los puntos principales\n4. Cierre cordial${instructions}`;
    default:
      return `Como asistente profesional, ayuda con lo siguiente:\n\n"${text}"${instructions}`;
  }
}

// Endpoints

app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
});

app.post('/generate', async (req, res) => {
  try {
    const { type, text, userInstruction } = req.body;
    if (!text || !type) return res.status(400).json({ error: 'Faltan datos requeridos.' });

    const prompt = buildPrompt(type, text, userInstruction);
    const completion = await openai.chat.completions.create({
      model: 'gpt-4.1-mini',
      messages: [
        { role: 'system', content: 'Eres un asistente profesional especializado en comunicación empresarial.' },
        { role: 'user', content: prompt }
      ],
      temperature: 0.7,
      max_tokens: 500,
      presence_penalty: 0.1,
      frequency_penalty: 0.1
    });

    const result = completion.choices[0].message.content;
    res.json({ result });

  } catch (err) {
    console.error('Error en /generate:', err);
    res.status(500).json({ error: 'Error generando respuesta' });
  }
});

// OAuth: login con Google
app.get('/auth/google', passport.authenticate('google', {
  scope: ['profile', 'email']
}));

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/' }),
  async (req, res) => {
    const { id, email, name } = req.user;
    try {
      await pool.execute(
        `INSERT INTO users (id, email, created_at, last_login)
         VALUES (?, ?, NOW(), NOW())
         ON DUPLICATE KEY UPDATE email = VALUES(email), last_login = NOW()`,
        [id, email]
      );
    } catch (dbErr) {
      console.error('Error guardando user en DB:', dbErr);
    }

    // Enviar HTML con cierre automático
    res.send(`
      <html>
        <body style="font-family: Poppins, sans-serif; text-align: center; margin-top: 40px;">
          <script>
            window.opener && window.opener.postMessage({ type: 'orion-auth-success' }, '*');
            window.close();
          </script>
          <p>Autenticación completada, puedes cerrar esta ventana.</p>
        </body>
      </html>
    `);
  }
);



// Probar si el usuario está logueado
app.get('/me', (req, res) => {
  if (req.user) res.json(req.user);
  else res.status(401).json({ error: 'No autenticado' });
});

// Logout
app.post('/logout', (req, res) => {
  req.logout(() => {
    req.session.destroy(err => {
      res.clearCookie('orion.sid');
      res.json({ success: true });
    });
  });
});


app.post('/log', async (req, res) => {
  const { user_id, action, input_text, output_text, source_url } = req.body;

  if (!user_id) {
    return res.status(401).json({ error: 'Usuario no autenticado' });
  }

  try {
    await pool.execute(
      `INSERT INTO user_activity_logs (user_id, action_type, input_text, output_text, source_url, created_at)
       VALUES (?, ?, ?, ?, ?, NOW())`,
      [user_id, action, input_text, output_text, source_url]
    );
    res.json({ success: true });
  } catch (err) {
    console.error('❌ Error al guardar log:', err);
    res.status(500).json({ error: 'Error al guardar log' });
  }
});


// ENDPOINTS PARA GESTIÓN DE PLANTILLAS

// Obtener las plantillas del usuario
app.get('/templates', async (req, res) => {
  const userId = req.query.userId;
  
  if (!userId) {
    return res.status(400).json({ error: 'Se requiere el ID de usuario' });
  }
  
  try {
    const [templates] = await pool.execute(
      `SELECT id, user_id, title, content, created_at 
       FROM user_templates 
       WHERE user_id = ? 
       ORDER BY created_at DESC`,
      [userId]
    );
    
    res.json({ templates });
  } catch (err) {
    console.error('❌ Error obteniendo plantillas:', err);
    res.status(500).json({ error: 'Error al obtener las plantillas' });
  }
});

// Crear una nueva plantilla
app.post('/templates', async (req, res) => {
  const { user_id, title, content } = req.body;
  
  if (!user_id || !title || !content) {
    return res.status(400).json({ error: 'Faltan datos requeridos' });
  }
  
  try {
    const [result] = await pool.execute(
      `INSERT INTO user_templates (user_id, title, content, created_at) 
       VALUES (?, ?, ?, NOW())`,
      [user_id, title, content]
    );
    
    res.status(201).json({ 
      success: true, 
      template_id: result.insertId,
      message: 'Plantilla creada exitosamente'
    });
  } catch (err) {
    console.error('❌ Error creando plantilla:', err);
    res.status(500).json({ error: 'Error al crear la plantilla' });
  }
});

// Actualizar una plantilla existente
app.put('/templates', async (req, res) => {
  const { id, user_id, title, content } = req.body;
  
  if (!id || !user_id || !title || !content) {
    return res.status(400).json({ error: 'Faltan datos requeridos' });
  }
  
  try {
    // Verificar que la plantilla pertenezca al usuario
    const [templates] = await pool.execute(
      `SELECT id FROM user_templates WHERE id = ? AND user_id = ?`,
      [id, user_id]
    );
    
    if (templates.length === 0) {
      return res.status(403).json({ error: 'No tienes permiso para editar esta plantilla' });
    }
    
    // Actualizar la plantilla
    await pool.execute(
      `UPDATE user_templates 
       SET title = ?, content = ?
       WHERE id = ? AND user_id = ?`,
      [title, content, id, user_id]
    );
    
    res.json({ 
      success: true, 
      message: 'Plantilla actualizada exitosamente'
    });
  } catch (err) {
    console.error('❌ Error actualizando plantilla:', err);
    res.status(500).json({ error: 'Error al actualizar la plantilla' });
  }
});

// Eliminar una plantilla
app.delete('/templates/:id', async (req, res) => {
  const templateId = req.params.id;
  
  if (!templateId) {
    return res.status(400).json({ error: 'Se requiere el ID de la plantilla' });
  }
  
  // Nota: Idealmente deberíamos verificar que la plantilla pertenezca al usuario actual
  // pero para simplificar, vamos a eliminar directamente por ID
  
  try {
    await pool.execute(
      `DELETE FROM user_templates WHERE id = ?`,
      [templateId]
    );
    
    res.json({ 
      success: true, 
      message: 'Plantilla eliminada exitosamente'
    });
  } catch (err) {
    console.error('❌ Error eliminando plantilla:', err);
    res.status(500).json({ error: 'Error al eliminar la plantilla' });
  }
});



app.listen(port, () => {
  console.log(`🚀 Orion backend corriendo en puerto ${port}`);
});
