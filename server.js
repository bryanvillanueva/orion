// Orion Backend - server.js
// Requiere: Node.js, Express y OpenAI SDK

const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const { OpenAI } = require('openai');

require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(bodyParser.json());

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// Función para construir prompts según tipo
function buildPrompt(type, text, userInstruction) {
  const instructions = userInstruction ? `\nTen en cuenta lo siguiente: ${userInstruction}` : '';
  switch (type) {
    case 'reply':
      return `Responde profesionalmente al siguiente mensaje de correo:\n"${text}"${instructions}`;
    case 'rewrite':
      return `Reescribe el siguiente texto con un tono profesional y claro:\n"${text}"${instructions}`;
    case 'translate':
      return `Traduce el siguiente texto al idioma especificado.\nTexto: "${text}"${instructions}`;
    case 'polish':
      return `Corrige y mejora el siguiente texto manteniendo el mensaje original:\n"${text}"${instructions}`;
    case 'tone-detect':
      return `Analiza el tono del siguiente mensaje y descríbelo brevemente:\n"${text}"${instructions}`;
    default:
      return `Actúa como asistente profesional. Ayuda con este texto:\n"${text}"${instructions}`;
  }
}

app.post('/generate', async (req, res) => {
  try {
    const { type, text, userInstruction } = req.body;
    if (!text || !type) {
      return res.status(400).json({ error: 'Faltan datos requeridos.' });
    }

    const prompt = buildPrompt(type, text, userInstruction);

    const completion = await openai.chat.completions.create({
      model: 'gpt-4.1-mini',
      messages: [{ role: 'user', content: prompt }],
      temperature: 0.7
    });

    const result = completion.choices[0].message.content;
    res.json({ result });
  } catch (err) {
    console.error('Error:', err);
    res.status(500).json({ error: 'Error al procesar la solicitud.' });
  }
});

app.listen(port, () => {
  console.log(`🚀 Orion backend corriendo en puerto ${port}`);
});
