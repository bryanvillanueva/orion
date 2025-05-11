// Orion Backend - server.js
// Requiere: Node.js, Express y OpenAI SDK

const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const { OpenAI } = require('openai');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');




const app = express();
const port = process.env.PORT || 3000;
app.set('trust proxy', 1);

app.use(session({
  secret: process.env.SESSION_SECRET || 'clave_segura',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // Usa true si usas HTTPS y proxy
}));


app.use(passport.initialize());
app.use(passport.session());

app.use(cors());
app.use(bodyParser.json());

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

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// Rate limiting middleware
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 100 // límite de 100 requests por ventana
});

app.use('/generate', limiter);

// Función para construir prompts según tipo
function buildPrompt(type, text, userInstruction) {
  const instructions = userInstruction ? `\nInstrucciones adicionales: ${userInstruction}` : '';
  
  switch (type) {
    case 'reply':
      return `Genera una respuesta profesional y cordial al siguiente mensaje:
      
Mensaje original: "${text}"

Instrucciones:
- Mantén un tono profesional pero amigable
- Sé conciso y directo
- Asegúrate de responder todos los puntos mencionados
${instructions}`;

    case 'rewrite':
      return `Reescribe el siguiente texto mejorando su claridad, profesionalismo y estructura:

Texto original: "${text}"

Instrucciones:
- Mantén el mensaje principal
- Mejora la gramática y puntuación
- Usa un tono profesional
- Hazlo más conciso si es posible
${instructions}`;

    case 'translate':
      // Detectar idioma automáticamente si no se especifica
      const targetLang = userInstruction || 'español';
      return `Traduce el siguiente texto al ${targetLang}:

Texto: "${text}"

Mantén el tono y estilo del original.`;

    case 'polish':
      return `Mejora el siguiente texto corrigiendo errores y puliendo el estilo:

Texto original: "${text}"

Instrucciones:
- Corrige errores gramaticales y ortográficos
- Mejora la fluidez y coherencia
- Mantén el tono original
- No cambies el significado
${instructions}`;

    case 'template':
      return `Genera una respuesta usando esta plantilla profesional:

Contexto: "${text}"

Crea una respuesta estructurada que incluya:
1. Saludo apropiado
2. Reconocimiento del mensaje
3. Respuesta a los puntos principales
4. Cierre cordial
${instructions}`;

    default:
      return `Como asistente profesional, ayuda con lo siguiente:

"${text}"
${instructions}`;
  }
}

// Endpoint de health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
});

// Endpoint principal de generación
app.post('/generate', async (req, res) => {
  try {
    const { type, text, userInstruction } = req.body;
    if (!text || !type) {
      return res.status(400).json({ error: 'Faltan datos requeridos.' });
    }

    const prompt = buildPrompt(type, text, userInstruction);

    const completion = await openai.chat.completions.create({
      model: 'gpt-4.1-mini', // Mantengo tu modelo original
      messages: [
        { 
          role: 'system', 
          content: 'Eres un asistente profesional especializado en comunicación empresarial. Tus respuestas deben ser claras, concisas y mantener un tono profesional.'
        },
        { role: 'user', content: prompt }
      ],
      temperature: 0.7,
      max_tokens: 500, // Limitar la longitud de respuesta
      presence_penalty: 0.1, // Evitar repeticiones
      frequency_penalty: 0.1
    });

    const result = completion.choices[0].message.content;
    res.json({ result });

  } catch (err) {
    if (err.response) {
      // Error de la API de OpenAI
      console.error('OpenAI API Error:', err.response.status, err.response.data);
      res.status(500).json({ 
        error: 'Error con el servicio de IA', 
        code: err.response.status 
      });
    } else if (err.request) {
      // Error de red
      console.error('Network Error:', err.message);
      res.status(503).json({ error: 'Servicio temporalmente no disponible' });
    } else {
      // Otros errores
      console.error('Error:', err.message);
      res.status(500).json({ error: 'Error interno del servidor' });
    }
  }
});

// Ruta de login
app.get('/auth/google', passport.authenticate('google', {
  scope: ['profile', 'email']
}));

// Ruta de callback
app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/' }),
  (req, res) => {
    // Puedes devolver un JWT o redirigir con el user en sesión
    res.json({ success: true, user: req.user });
  }
);

// Ruta de prueba
app.get('/me', (req, res) => {
  if (req.user) res.json(req.user);
  else res.status(401).json({ error: 'No autenticado' });
});


app.listen(port, () => {
  console.log(`🚀 Orion backend corriendo en puerto ${port}`);
});