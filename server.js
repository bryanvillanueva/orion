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
  store: sessionStore,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false,
    httpOnly: true,      // 👈 Agregar esto por seguridad
    maxAge: 1000 * 60 * 60 * 24 * 7,
    sameSite: 'lax'      // 👈 Agregar esto para CORS
  }
}));

app.use(passport.initialize());
app.use(passport.session());

app.use((req, res, next) => {
  // Permitir cualquier origen para las peticiones de extensiones
  res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  
  // Responder a peticiones OPTIONS (preflight)
  if (req.method === 'OPTIONS') {
    res.sendStatus(200);
  } else {
    next();
  }
});

// Mantener también tu configuración de CORS actual como respaldo:
app.use(cors({
  origin: true,  // Permitir cualquier origen
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

app.use(bodyParser.json());

// Configurar OpenAI
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// Configurar Passport con Google
passport.serializeUser((user, done) => {
  console.log('📝 SERIALIZANDO usuario:', user);
  done(null, user);
});

passport.deserializeUser(async (user, done) => {
  try {
    console.log("🔍 DESERIALIZANDO usuario recibido:", user);
    
    if (!user || !user.id) {
      console.log("❌ Usuario inválido para deserializar");
      return done(null, false);
    }

    const [rows] = await pool.execute(
      `SELECT u.id, u.email, u.orion_user_id, u.created_at, u.last_login,
              o.full_name, o.username, o.email_contact
       FROM users u
       LEFT JOIN orion_users o ON u.orion_user_id = o.id
       WHERE u.id = ? LIMIT 1`,
      [user.id]
    );

    console.log("🔍 RESULTADO query deserialización:", rows);

    if (rows.length === 0) {
      console.log("⚠️ Usuario no encontrado en BD");
      return done(null, false);
    }

    const userData = {
      ...rows[0],
      name: user.name
    };

    console.log("✅ Usuario deserializado:", userData);
    return done(null, userData);
  } catch (err) {
    console.error("❌ Error en deserializeUser:", err);
    return done(err, null);
  }
});

app.get('/debug-session', (req, res) => {
  res.json({
    isAuthenticated: req.isAuthenticated(),
    sessionID: req.sessionID,
    session: req.session,
    user: req.user,
    passport: req.session?.passport
  });
});

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
    console.log('🔍 CALLBACK - req.user inicial:', req.user);
    console.log('🔍 CALLBACK - req.session ANTES:', req.session);
    console.log('🔍 CALLBACK - req.isAuthenticated():', req.isAuthenticated());
    
    try {
      const googleId = req.user.id;
      const email = req.user.email;
      const name = req.user.name;

      console.log('🔍 CALLBACK - Datos de Google:', { googleId, email, name });

      // Buscar si la cuenta ya está registrada
      const [userRows] = await pool.execute(
        `SELECT * FROM users WHERE id = ? LIMIT 1`,
        [googleId]
      );

      let orionUserId = null;

      if (userRows.length === 0) {
        // Registrar nueva cuenta de acceso (sin orion_user_id aún)
        await pool.execute(
          `INSERT INTO users (id, email, created_at, last_login)
           VALUES (?, ?, NOW(), NOW())`,
          [googleId, email]
        );
      } else {
        // Si ya existe, obtener el orion_user_id y actualizar login
        orionUserId = userRows[0].orion_user_id;
        await pool.execute(
          `UPDATE users SET last_login = NOW() WHERE id = ?`,
          [googleId]
        );
      }

      // Armar objeto de respuesta
      const userObject = {
        id: googleId,
        email,
        name,
        orion_user_id: orionUserId || null
      };

      const needsSetup = !orionUserId;


      console.log('🔍 CALLBACK - req.session DESPUÉS:', req.session);
      console.log('🔍 CALLBACK - userObject final:', userObject);

      // Enviar los datos al frontend (popup.html) usando postMessage
      res.send(`
        <html>
          <body style="font-family: Poppins, sans-serif; text-align: center; margin-top: 40px;">
            <script>
              const user = ${JSON.stringify(userObject)};
              const needsSetup = ${JSON.stringify(needsSetup)};
              
              if (window.opener) {
                window.opener.postMessage({ type: 'orion-auth-success', user, needsSetup }, '*');
                window.close();
              } else {
                document.body.innerHTML = '<p>No se pudo completar la autenticación.</p>';
              }
            </script>
            <p>Autenticación completada, puedes cerrar esta ventana.</p>
          </body>
        </html>
      `);
    } catch (err) {
      console.error("❌ Error en callback:", err);
      res.status(500).send("Error al autenticar usuario.");
    }
  }
);

// Endpoint para configurar el usuario
app.post('/user/setup', async (req, res) => {
  if (!req.user || !req.user.id) {
    return res.status(401).json({ error: 'No autenticado' });
  }

  const { full_name, username, email_contact } = req.body;

  if (!full_name || !username || !email_contact) {
    return res.status(400).json({ error: 'Todos los campos son requeridos.' });
  }

  try {
    // Verificar si este usuario ya está vinculado a un orion_user
    const [existing] = await pool.execute(
      'SELECT orion_user_id FROM users WHERE id = ? LIMIT 1',
      [req.user.id]
    );

    if (existing.length > 0 && existing[0].orion_user_id) {
      return res.status(400).json({
        error: 'Este usuario ya está vinculado a un perfil de Orion.'
      });
    }

    // Crear nuevo orion_user
    const [result] = await pool.execute(
      `INSERT INTO orion_users (full_name, username, email_contact)
       VALUES (?, ?, ?)`,
      [full_name, username, email_contact]
    );

    const orionUserId = result.insertId;

    // Asociar ese orion_user al usuario de Gmail
    await pool.execute(
      `UPDATE users SET orion_user_id = ? WHERE id = ?`,
      [orionUserId, req.user.id]
    );

    // Devolver información al frontend
    res.json({
      success: true,
      user: {
        id: req.user.id,
        email: req.user.email,
        name: req.user.name,
        orion_user_id: orionUserId,
        full_name,
        username,
        email_contact
      }
    });
  } catch (err) {
    console.error('❌ Error en /user/setup:', err);
    res.status(500).json({ error: 'Error interno al registrar el perfil' });
  }
});




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


// Ya que estás usando sesiones, puedes usar req.user directamente
app.post('/log', async (req, res) => {
  if (!req.user || !req.user.id) {
    return res.status(401).json({ error: 'Usuario no autenticado' });
  }

  const { action, input_text, output_text, source_url } = req.body;
  const orionUserId = req.user.orion_user_id;

  if (!orionUserId) {
    return res.status(400).json({ error: 'El usuario aún no ha completado el setup de perfil.' });
  }

  try {
    await pool.execute(
      `INSERT INTO user_activity_logs (user_id, action_type, input_text, output_text, source_url, created_at)
       VALUES (?, ?, ?, ?, ?, NOW())`,
      [orionUserId, action, input_text, output_text, source_url]
    );

    res.json({ success: true });
  } catch (err) {
    console.error('❌ Error al guardar log:', err);
    res.status(500).json({ error: 'Error al guardar log' });
  }
});



// ENDPOINTS PARA GESTIÓN DE PLANTILLAS

// Manejo específico de OPTIONS para templates
app.options('/templates', (req, res) => {
  res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  res.sendStatus(200);
});

app.options('/templates/:id', (req, res) => {
  res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  res.sendStatus(200);
});

// Obtener las plantillas del usuario
app.get('/templates', async (req, res) => {
  console.log('🔍 Headers recibidos:', req.headers);
  console.log('🔍 Cookie header:', req.headers.cookie);
  console.log('🔍 Origin:', req.headers.origin);
  console.log('🔍 User-Agent:', req.headers['user-agent']);
  console.log('🔍 GET /templates - req.user:', req.user);
  console.log('🔍 GET /templates - session:', req.session);
  
  if (!req.user || !req.user.orion_user_id) {
    return res.status(401).json({ error: 'No autenticado o sin perfil completo' });
  }

  try {
    const [templates] = await pool.execute(
      `SELECT id, user_id, title, content, created_at 
       FROM user_templates 
       WHERE user_id = ? 
       ORDER BY created_at DESC`,
      [req.user.orion_user_id]
    );

    res.json({ templates });
  } catch (err) {
    console.error('❌ Error obteniendo plantillas:', err);
    res.status(500).json({ error: 'Error al obtener las plantillas' });
  }
});


// Crear una nueva plantilla
app.post('/templates', async (req, res) => {
  console.log('📌 Sesión:', req.session);
  console.log('📌 Usuario:', req.user);
  console.log('📌 Sesión completa:', req.session);
  console.log('📌 Usuario completo:', req.user);
  console.log('📌 orion_user_id:', req.user?.orion_user_id);
  if (!req.user || !req.user.orion_user_id) {
    return res.status(401).json({ error: 'No autenticado o sin perfil completo' });
  }

  const { title, content } = req.body;

  if (!title || !content) {
    return res.status(400).json({ error: 'Faltan datos requeridos' });
  }

  try {
    const [result] = await pool.execute(
      `INSERT INTO user_templates (user_id, title, content, created_at) 
       VALUES (?, ?, ?, NOW())`,
      [req.user.orion_user_id, title, content]
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
// Actualizar una plantilla existente
app.put('/templates', async (req, res) => {
  if (!req.user || !req.user.orion_user_id) {
    return res.status(401).json({ error: 'No autenticado o sin perfil completo' });
  }

  const { id, title, content } = req.body;

  if (!id || !title || !content) {
    return res.status(400).json({ error: 'Faltan datos requeridos' });
  }

  try {
    // Verificar que la plantilla pertenezca al usuario autenticado
    const [templates] = await pool.execute(
      `SELECT id FROM user_templates WHERE id = ? AND user_id = ?`,
      [id, req.user.orion_user_id]
    );

    if (templates.length === 0) {
      return res.status(403).json({ error: 'No tienes permiso para editar esta plantilla' });
    }

    // Actualizar la plantilla
    await pool.execute(
      `UPDATE user_templates 
       SET title = ?, content = ?
       WHERE id = ? AND user_id = ?`,
      [title, content, id, req.user.orion_user_id]
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

  if (!req.user || !req.user.orion_user_id) {
    return res.status(401).json({ error: 'No autenticado o sin perfil completo' });
  }

  try {
    const [templates] = await pool.execute(
      `SELECT id FROM user_templates WHERE id = ? AND user_id = ?`,
      [templateId, req.user.orion_user_id]
    );

    if (templates.length === 0) {
      return res.status(403).json({ error: 'No tienes permiso para eliminar esta plantilla' });
    }

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

// Debuggind Endpoint

app.get('/debug-user', async (req, res) => {
  if (!req.user) {
    return res.json({ error: 'No hay usuario en sesión' });
  }
  
  try {
    // Buscar manualmente el usuario
    const [userRows] = await pool.execute(
      `SELECT u.*, o.full_name, o.username, o.email_contact
       FROM users u
       LEFT JOIN orion_users o ON u.orion_user_id = o.id
       WHERE u.id = ? LIMIT 1`,
      [req.user.id]
    );
    
    res.json({
      sessionUser: req.user,
      dbUser: userRows[0] || null,
      hasOrionId: !!req.user.orion_user_id
    });
  } catch (err) {
    res.json({ error: err.message });
  }
});

app.listen(port, () => {
  console.log(`🚀 Orion backend corriendo en puerto ${port}`);
});
