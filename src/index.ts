import type { NextFunction, Request, Response } from 'express'
import type { Store } from 'express-session'
import type { Database } from 'sqlite'
import fs from 'node:fs'
import path from 'node:path'

import { fileURLToPath } from 'node:url'
import bcrypt from 'bcrypt'
import SQLiteStoreFactory from 'connect-sqlite3'
import express from 'express'
import session from 'express-session'
import multer from 'multer'
import cron from 'node-cron'
import pdfParse from 'pdf-parse'
import { open } from 'sqlite'
import sqlite3 from 'sqlite3'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const app = express()
const upload = multer({ dest: 'temp/' })

app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(express.static(path.join(__dirname, 'public')))

const SQLiteStore = SQLiteStoreFactory(session) as unknown as { new (options?: any): Store }
app.use(session({
  store: new SQLiteStore({ db: 'sessions.sqlite', dir: './' }),
  secret: 'e334aa515718d7613f52646f0e92a7ff8bd2b2b81bbde28d27698c4a1e9d8fc8',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false },
}))

app.set('view engine', 'ejs')
app.set('views', path.join(__dirname, 'views'))

async function deductCredit(userId: number): Promise<boolean> {
  const db = await initDb()
  const user = await db.get('SELECT credits FROM users WHERE id = ?', [userId])
  if (user && user.credits > 0) {
    await db.run('UPDATE users SET credits = credits - 1 WHERE id = ?', [userId])
    await db.close()
    return true
  }
  await db.close()
  return false
}

cron.schedule('0 0 * * *', async () => {
  const db = await initDb()
  await db.run('UPDATE users SET credits = 20')
  await db.close()
})

function levenshtein(a: string, b: string): number {
  const dp: number[][] = Array.from({ length: a.length + 1 })
    .fill(null)
    .map(() => Array.from({ length: b.length + 1 }).fill(0)) as number[][]

  for (let i = 0; i <= a.length; i++) dp[i][0] = i
  for (let j = 0; j <= b.length; j++) dp[0][j] = j

  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      if (a[i - 1] === b[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1]
      }
      else {
        dp[i][j] = Math.min(dp[i - 1][j - 1], dp[i][j - 1], dp[i - 1][j]) + 1
      }
    }
  }
  return dp[a.length][b.length]
}

function wordFrequency(text: string): Map<string, number> {
  const words = text.toLowerCase().match(/\b[a-z]+\b/gi) || []
  const freqMap = new Map<string, number>()
  words.forEach(word => freqMap.set(word, (freqMap.get(word) || 0) + 1))
  return freqMap
}

function cosineSimilarity(freq1: Map<string, number>, freq2: Map<string, number>): number {
  const words = new Set([...freq1.keys(), ...freq2.keys()])
  let dotProduct = 0; let magA = 0; let magB = 0

  words.forEach((word) => {
    const val1 = freq1.get(word) || 0
    const val2 = freq2.get(word) || 0
    dotProduct += val1 * val2
    magA += val1 * val1
    magB += val2 * val2
  })

  return magA && magB ? dotProduct / (Math.sqrt(magA) * Math.sqrt(magB)) : 0
}

function calculateSimilarity(text1: string, text2: string): number {
  if (!text1 || !text2)
    return 0
  const levDist = levenshtein(text1, text2)
  const maxLen = Math.max(text1.length, text2.length)
  const levScore = 1 - levDist / maxLen

  const freq1 = wordFrequency(text1)
  const freq2 = wordFrequency(text2)
  const cosineScore = cosineSimilarity(freq1, freq2)

  return (levScore + cosineScore) / 2
}

async function initDb(): Promise<Database> {
  const db = await open({ filename: 'database.db', driver: sqlite3.Database })

  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      firstname TEXT NOT NULL,
      lastname TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      credits INTEGER DEFAULT 20
    )
  `)

  await db.exec(`
    CREATE TABLE IF NOT EXISTS files (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      filename TEXT NOT NULL,
      content TEXT NOT NULL,
      mimetype TEXT NOT NULL,
      size INTEGER NOT NULL,
      uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `)

  await db.exec(`
    CREATE TABLE IF NOT EXISTS matches (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  file1_id INTEGER NOT NULL,
  file2_id INTEGER NOT NULL,
  similarity_score REAL NOT NULL,
  FOREIGN KEY (file1_id) REFERENCES files(id) ON DELETE CASCADE,
  FOREIGN KEY (file2_id) REFERENCES files(id) ON DELETE CASCADE
);
  `)

  return db
}

async function hashPassword(password: string): Promise<string> {
  return await bcrypt.hash(password, 10)
}

async function comparePassword(password: string, hashedPassword: string): Promise<boolean> {
  return await bcrypt.compare(password, hashedPassword)
}

function isAuthenticated(req: Request, res: Response, next: NextFunction): void {
  if (req.session.user)
    return next()
  res.redirect('/login')
}

app.get('/login', (req, res) => res.render('login', { message: null, title: 'Login' }))

app.get('/signup', (req, res) => res.render('signup', { message: null, title: 'Sign Up' }))

app.post('/signup', async (req, res) => {
  const { firstname, lastname, email, password, confirmPassword } = req.body
  if (password !== confirmPassword)
    return res.render('signup', { message: 'Passwords do not match', title: 'Sign Up' })

  const db = await initDb()
  try {
    const hashedPassword = await hashPassword(password)
    await db.run('INSERT INTO users (firstname, lastname, email, password) VALUES (?, ?, ?, ?)', [firstname, lastname, email, hashedPassword])
    res.redirect('/login')
  }
  catch (error) {
    console.warn(error)
    res.render('signup', { message: 'An error occurred. Email might already be registered.', title: 'Sign Up' })
  }
  finally {
    await db.close()
  }
})

app.post('/login', async (req, res) => {
  const { email, password } = req.body
  const db = await initDb()

  try {
    const user = await db.get('SELECT * FROM users WHERE email = ?', [email])
    if (user && await comparePassword(password, user.password)) {
      req.session.user = { id: user.id, email: user.email, firstname: user.firstname, lastname: user.lastname }
      res.redirect('/')
    }
    else {
      res.render('login', { message: 'Invalid email or password', title: 'Login' })
    }
  }
  catch (error) {
    console.warn(error)
    res.render('login', { message: 'An error occurred while processing your request. Please try again.', title: 'Login' })
  }
  finally {
    await db.close()
  }
})

app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error(err)
      res.status(500).send('Error logging out.')
    }
    else {
      res.redirect('/')
    }
  })
})

app.get('/', isAuthenticated, (req, res) => res.render('layout', { user: req.session.user, title: 'Dashboard', body: 'dashboard' }))

app.get('/scans/:id', isAuthenticated, async (req, res) => {
  const db = await initDb()
  const fileId = req.params.id

  const file = await db.get('SELECT * FROM files WHERE id = ?', [fileId])
  if (!file) {
    res.status(404).send('File not found')
    return
  }

  const matches = await db.all(
    `SELECT f.id, f.filename, f.mimetype, f.size, f.uploaded_at, m.similarity_score
     FROM matches m
     JOIN files f ON (m.file2_id = f.id OR m.file1_id = f.id)
     WHERE (m.file1_id = ? OR m.file2_id = ?) AND f.id != ?
     ORDER BY m.similarity_score DESC`,
    [fileId, fileId, fileId],
  )

  res.render('layout', { user: req.session.user, file, matches, title: 'Scan', body: 'scan' })
})

app.post('/upload', isAuthenticated, upload.single('file'), async (req, res) => {
  const file = req.file
  const db = await initDb()

  if (!file) { res.status(400).json({ error: 'No file uploaded.' }); return }

  if (req.session.user && !(await deductCredit(req.session.user.id))) {
    res.status(403).json({ error: 'Daily upload limit reached. Try again tomorrow.' })
    return
  }

  let extractedText = ''
  try {
    const filePath = path.resolve(file.path)

    if (file.mimetype === 'application/pdf') {
      const dataBuffer = fs.readFileSync(filePath)
      const pdfData = await pdfParse(dataBuffer)
      extractedText = pdfData.text
    }
    else if (file.mimetype.startsWith('text/')) {
      extractedText = fs.readFileSync(filePath, 'utf-8')
    }
    else {
      res.status(400).json({ error: 'Unsupported file type.' })
      return
    }

    const result = await db.run(
      'INSERT INTO files (user_id, filename, content, mimetype, size) VALUES (?, ?, ?, ?, ?)',
      [req?.session?.user?.id, file.originalname, extractedText, file.mimetype, file.size],
    )

    fs.unlinkSync(filePath)

    res.status(200).json({ message: 'File uploaded and text saved successfully.', fileId: result.lastID })
  }
  catch (error) {
    console.error(error)
    res.status(500).json({ error: 'Error processing file.' })
  }
  finally {
    await db.close()
  }
})

app.post('/compare/:id', isAuthenticated, async (req, res) => {
  const { id } = req.params
  const db = await initDb()

  try {
    const fileToCompare = await db.get('SELECT * FROM files WHERE id = ?', [id])
    if (!fileToCompare) {
      res.status(404).json({ error: 'Document not found' }); return
    }

    const existingFiles = await db.all('SELECT * FROM files WHERE id != ?', [id])

    let bestMatch = null
    let highestScore = 0

    for (const file of existingFiles) {
      const score = calculateSimilarity(fileToCompare.content, file.content)

      if (score > highestScore) {
        highestScore = score
        bestMatch = file
      }

      await db.run('INSERT INTO matches (file1_id, file2_id, similarity_score) VALUES (?, ?, ?)', [fileToCompare.id, file.id, score])
    }

    res.status(200).json({
      message: 'Comparison complete',
      bestMatch: bestMatch ? { id: bestMatch.id, filename: bestMatch.filename, score: highestScore } : null,
    })
  }
  catch (error) {
    console.error(error)
    res.status(500).json({ error: 'Error processing document comparison' })
  }
  finally {
    await db.close()
  }
})

app.listen(3000, () => console.warn('Server is running on http://localhost:3000'))
