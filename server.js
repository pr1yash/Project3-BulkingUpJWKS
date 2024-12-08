import express from 'express';
import jwt from 'jsonwebtoken';
import jose from 'node-jose';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import fs from 'fs';
import path from 'path';
import { v4 as uuidv4 } from 'uuid';
import argon2 from 'argon2';
import crypto from 'crypto';
import dotenv from 'dotenv';
import { RateLimiterMemory } from 'rate-limiter-flexible';

const rateLimiter = new RateLimiterMemory({
  points: 10, // Allows up to 10 requests
  duration: 1, // Within one second
});

dotenv.config();

const app = express();
const port = 8080;

app.use(express.json());

let db;
const dbPath = path.join(process.cwd(), 'totally_not_my_privateKeys.db');

// Key used for AES encryption
const AES_KEY = process.env.NOT_MY_KEY;

async function initDB() {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });

    // Create necessary tables if they don't already exist
    await db.exec(`
      CREATE TABLE IF NOT EXISTS keys (
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT NOT NULL,
        exp INTEGER NOT NULL
      );
      
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        email TEXT UNIQUE,
        date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS auth_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_ip TEXT NOT NULL,
        request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        user_id INTEGER
      );
    `);

    console.log('Database setup is complete at:', dbPath);
  } catch (error) {
    console.error('Database initialization failed:', error);
    throw error;
  }
}

function encryptData(data) {
  const iv = crypto.randomBytes(16); // Generate a random IV
  const cipher = crypto.createCipheriv('aes-256-cbc', AES_KEY, iv);
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted; // Concatenate IV and the encrypted data
}

function decryptData(data) {
  const [ivHex, encryptedData] = data.split(':'); // Separate IV from encrypted content
  const iv = Buffer.from(ivHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', AES_KEY, iv);
  let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

async function storeKeyPair(expiryInSeconds) {
  const key = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });
  const serializedKey = encryptData(key.toPEM(true));
  const expiration = Math.floor(Date.now() / 1000) + expiryInSeconds;

  await db.run(`INSERT INTO keys (key, exp) VALUES (?, ?)`, [serializedKey, expiration]);
}

async function getKeyFromDB(expired = false) {
  const now = Math.floor(Date.now() / 1000);
  const condition = expired ? 'exp <= ?' : 'exp > ?';

  const row = await db.get(`SELECT key FROM keys WHERE ${condition} LIMIT 1`, [now]);

  if (!row) throw new Error('No valid key available');

  // Decrypt key in memory only
  const decryptedKey = decryptData(row.key);
  return jose.JWK.asKey(decryptedKey, 'pem'); // Convert PEM format to JWK
}

// Endpoint for user registration
app.post('/register', async (req, res) => {
  try {
    const { username, email } = req.body;
    if (!username || !email) {
      return res.status(400).send('Username and email are required fields.');
    }

    const password = uuidv4();
    const hashedPassword = await argon2.hash(password);

    await db.run(
      `INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)`,
      [username, hashedPassword, email]
    );

    res.status(201).json({ password });
  } catch (error) {
    res.status(500).send('Registration error: ' + error.message);
  }
});

// Record details of authentication attempts
async function logAuthRequest(ip, userId) {
  await db.run(
    `INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)`,
    [ip, userId]
  );
}

// Endpoint for authentication
app.post('/auth', async (req, res) => {
  try {
    const ip = req.ip || req.connection.remoteAddress;
    await rateLimiter.consume(ip);

    const expired = req.query.expired === 'true';
    const key = await getKeyFromDB(expired);

    const payload = {
      user: 'sampleUser',
      iat: Math.floor(Date.now() / 1000),
      exp: expired
        ? Math.floor(Date.now() / 1000) - 3600
        : Math.floor(Date.now() / 1000) + 3600,
    };

    const token = jwt.sign(payload, key.toPEM(true), {
      algorithm: 'RS256',
      header: { kid: key.kid, typ: 'JWT' },
    });

    const userId = 1;
    await logAuthRequest(ip, userId);

    res.send(token);
  } catch (error) {
    if (error instanceof RateLimiterMemory.RateLimiterRes) {
      res.status(429).send('Too Many Requests'); // Updated to match the test expectation
    } else {
      res.status(500).send('Internal Server Error');
    }
  }
});

// Endpoint to retrieve all active keys in JWKS format
app.get('/.well-known/jwks.json', async (req, res) => {
  try {
    const now = Math.floor(Date.now() / 1000);

    const rows = await db.all(`SELECT key FROM keys WHERE exp > ?`, [now]);

    const keys = await Promise.all(
      rows.map(async (row) => {
        const key = await jose.JWK.asKey(decryptData(row.key), 'pem');
        return key.toJSON();
      })
    );

    res.setHeader('Content-Type', 'application/json');
    res.json({ keys });
  } catch (error) {
    res.status(500).send('Error fetching keys: ' + error.message);
  }
});

// Set up the database, generate keys, and start the application
async function startServer() {
  try {
    await initDB(); // Ensure the database is initialized
    await storeKeyPair(-3600); // Save an expired key
    await storeKeyPair(3600); // Save a valid key

    app.listen(port, () => {
      console.log(`Server is live at http://localhost:${port}`);
    });
  } catch (error) {
    console.error('Server startup failed:', error);
  }
}

startServer();
export { app };
