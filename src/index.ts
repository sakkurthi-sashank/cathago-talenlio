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

async function initDb(): Promise<Database> {
  const db = await open({ filename: 'database.db', driver: sqlite3.Database })

  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      firstname TEXT NOT NULL,
      lastname TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      credits INTEGER DEFAULT 20,
      role TEXT DEFAULT 'user' CHECK (role IN ('user', 'admin'))
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

  await db.exec(`
    CREATE TABLE IF NOT EXISTS credit_requests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      credits_requested INTEGER NOT NULL,
      reason TEXT NOT NULL,
      status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'denied')),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      processed_at TIMESTAMP,
      processed_by INTEGER,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (processed_by) REFERENCES users(id)
    );
  `)

  await db.exec(`
    CREATE TABLE IF NOT EXISTS scan_statistics (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      scan_date DATE DEFAULT CURRENT_DATE,
      scan_count INTEGER DEFAULT 0,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      UNIQUE(user_id, scan_date)
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

function isAuthenticated(req: Request, res: Response, next: NextFunction): void {
  if (req.session.user)
    return next()
  res.redirect('/login')
}

async function isAdmin(req: Request, res: Response, next: NextFunction): Promise<void> {
  const db = await initDb()

  if (!req.session.user) {
    res.status(401).send('Unauthorized')
    return
  }

  const user = await db.get('SELECT role FROM users WHERE id = ?', [req.session.user?.id])

  if (user && user.role === 'admin')
    return next()
  res.status(403).send('Access denied')
}

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

async function updateScanStatistics(userId: number): Promise<void> {
  const db = await initDb()
  try {
    // Try to update existing record
    const result = await db.run(
      `UPDATE scan_statistics 
       SET scan_count = scan_count + 1 
       WHERE user_id = ? AND scan_date = CURRENT_DATE`,
      [userId],
    )

    // If no record exists, create one
    if (result.changes === 0) {
      await db.run(
        `INSERT INTO scan_statistics (user_id, scan_count) 
         VALUES (?, 1)`,
        [userId],
      )
    }
  }
  catch (error) {
    console.error('Error updating scan statistics:', error)
  }
  finally {
    await db.close()
  }
}

cron.schedule('0 0 * * *', async () => {
  const db = await initDb()
  await db.run('UPDATE users SET credits = 20')
  await db.close()
})

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
      req.session.user = {
        id: user.id,
        email: user.email,
        firstname: user.firstname,
        lastname: user.lastname,
        role: user.role,
        credits: user.credits,
      }
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

app.get('/', isAuthenticated, async (req, res) => {
  const db = await initDb()
  try {
    if (req.session.user) {
      const userInfo = await db.get('SELECT credits FROM users WHERE id = ?', [req.session.user.id])
      if (userInfo) {
        req.session.user.credits = userInfo.credits
      }
    }

    res.render('dashboard', {
      user: req.session.user,
    })
  }
  catch (error) {
    console.error(error)
    res.status(500).send('Error loading dashboard')
  }
  finally {
    await db.close()
  }
})

app.get('/profile', isAuthenticated, async (req, res) => {
  const db = await initDb()
  try {
    const userId = req.session.user?.id

    const userFiles = await db.all(
      'SELECT * FROM files WHERE user_id = ? ORDER BY uploaded_at DESC',
      [userId],
    )

    const creditRequests = await db.all(
      'SELECT * FROM credit_requests WHERE user_id = ? ORDER BY created_at DESC',
      [userId],
    )

    const userInfo = await db.get('SELECT * FROM users WHERE id = ?', [userId])
    if (userInfo && req.session.user) {
      req.session.user.credits = userInfo.credits
    }

    res.render('profile', {
      user: req.session.user,
      files: userFiles,
      creditRequests,
    })
  }
  catch (error) {
    console.error(error)
    res.status(500).send('Error loading profile')
  }
  finally {
    await db.close()
  }
})

app.get('/scans', isAuthenticated, async (req, res) => {
  const db = await initDb()
  try {
    const userId = req.session.user?.id

    const userFiles = await db.all(
      'SELECT * FROM files WHERE user_id = ? ORDER BY uploaded_at DESC',
      [userId],
    )

    res.json(userFiles)
  }
  catch (error) {
    console.error(error)
    res.status(500).send('Error loading scans')
  }
  finally {
    await db.close()
  }
})

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

  res.render('scan', { user: req.session.user, file, matches })
})

app.post('/upload', isAuthenticated, upload.single('file'), async (req, res) => {
  const file = req.file
  const db = await initDb()

  if (!file) { res.status(400).json({ error: 'No file uploaded.' }); return }

  if (req.session.user && !(await deductCredit(req.session.user.id))) {
    res.status(403).json({ error: 'Daily upload limit reached. Try again tomorrow or request more credits.' })
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

    if (req.session.user) {
      await updateScanStatistics(req.session.user.id)
    }

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

app.get('/credits/history', isAuthenticated, async (req, res) => {
  const db = await initDb()

  try {
    const userId = req.session.user?.id
    const creditRequests = await db.all('SELECT * FROM credit_requests WHERE user_id = ? ORDER BY created_at DESC', [userId])

    res.json(creditRequests)
  }
  catch (error) {
    console.error(error)
    res.status(500).send('Error loading credit history')
  }
  finally {
    await db.close()
  }
})

app.post('/credits/request', isAuthenticated, async (req, res) => {
  const { creditsRequested, reason } = req.body
  const userId = req.session.user?.id

  if (!userId || !creditsRequested || !reason) {
    res.status(400).json({ error: 'Missing required fields' })
    return
  }

  const db = await initDb()
  try {
    await db.run(
      'INSERT INTO credit_requests (user_id, credits_requested, reason) VALUES (?, ?, ?)',
      [userId, creditsRequested, reason],
    )
    res.status(200).json({ message: 'Credit request submitted successfully' })
  }
  catch (error) {
    console.error(error)
    res.status(500).json({ error: 'Error submitting credit request' })
  }
  finally {
    await db.close()
  }
})

app.get('/admin/credit-requests', isAuthenticated, isAdmin, async (req, res) => {
  const db = await initDb()
  try {
    const requests = await db.all(`
      SELECT cr.*, u.firstname, u.lastname, u.email 
      FROM credit_requests cr
      JOIN users u ON cr.user_id = u.id
      WHERE cr.status = 'pending'
      ORDER BY cr.created_at DESC
    `)

    res.render('credit-requests', {
      user: req.session.user,
      requests,
    })
  }
  catch (error) {
    console.error(error)
    res.status(500).send('Error loading credit requests')
  }
  finally {
    await db.close()
  }
})

app.post('/admin/credit-requests/:id', isAuthenticated, isAdmin, async (req, res) => {
  const { id } = req.params
  const { action } = req.body
  const adminId = req.session.user?.id

  if (!['approve', 'deny'].includes(action)) {
    res.status(400).json({ error: 'Invalid action' })
    return
  }

  const db = await initDb()
  try {
    const request = await db.get('SELECT * FROM credit_requests WHERE id = ?', [id])
    if (!request) {
      res.status(404).json({ error: 'Request not found' })
      return
    }

    await db.run(
      'UPDATE credit_requests SET status = ?, processed_at = CURRENT_TIMESTAMP, processed_by = ? WHERE id = ?',
      [action === 'approve' ? 'approved' : 'denied', adminId, id],
    )

    if (action === 'approve') {
      await db.run(
        'UPDATE users SET credits = credits + ? WHERE id = ?',
        [request.credits_requested, request.user_id],
      )
    }

    res.status(200).json({ message: `Request ${action === 'approve' ? 'approved' : 'denied'} successfully` })
  }
  catch (error) {
    console.error(error)
    res.status(500).json({ error: `Error ${action === 'approve' ? 'approving' : 'denying'} request` })
  }
  finally {
    await db.close()
  }
})

app.get('/admin/user-management', isAuthenticated, isAdmin, async (req, res) => {
  const db = await initDb()
  try {
    const users = await db.all('SELECT id, firstname, lastname, email, credits, role FROM users')

    res.render('admin-dashboard', {
      user: req.session.user,
      users,
    })
  }
  catch (error) {
    console.error(error)
    res.status(500).send('Error loading users')
  }
  finally {
    await db.close()
  }
})

app.post('/admin/user/:id/credits', isAuthenticated, isAdmin, async (req, res) => {
  const { id } = req.params
  const { credits } = req.body

  if (!credits) {
    res.status(400).json({ error: 'Credits amount is required' })
    return
  }

  const db = await initDb()
  try {
    await db.run('UPDATE users SET credits = ? WHERE id = ?', [credits, id])
    res.status(200).json({ message: 'Credits updated successfully' })
  }
  catch (error) {
    console.error(error)
    res.status(500).json({ error: 'Error updating credits' })
  }
  finally {
    await db.close()
  }
})

app.post('/admin/user/:id/role', isAuthenticated, isAdmin, async (req, res) => {
  const { id } = req.params
  const { role } = req.body

  if (!role || !['user', 'admin'].includes(role)) {
    res.status(400).json({ error: 'Valid role is required' })
    return
  }

  const db = await initDb()
  try {
    await db.run('UPDATE users SET role = ? WHERE id = ?', [role, id])
    res.status(200).json({ message: 'Role updated successfully' })
  }
  catch (error) {
    console.error(error)
    res.status(500).json({ error: 'Error updating role' })
  }
  finally {
    await db.close()
  }
})

app.get('/admin/analytics', isAuthenticated, isAdmin, async (req, res) => {
  const db = await initDb()
  try {
    const topUsers = await db.all(`
      SELECT u.id, u.firstname, u.lastname, COUNT(f.id) as scan_count
      FROM users u
      LEFT JOIN files f ON u.id = f.user_id
      GROUP BY u.id
      ORDER BY scan_count DESC
      LIMIT 10
    `)

    const dailyStats = await db.all(`
      SELECT scan_date, SUM(scan_count) as total_scans
      FROM scan_statistics
      GROUP BY scan_date
      ORDER BY scan_date DESC
      LIMIT 30
    `)

    const creditStats = await db.all(`
      SELECT u.id, u.firstname, u.lastname, u.credits, 
             (SELECT COUNT(*) FROM credit_requests cr WHERE cr.user_id = u.id) as request_count
      FROM users u
      ORDER BY request_count DESC
      LIMIT 10
    `)

    res.render('admin-analytics', {
      user: req.session.user,
      topUsers,
      dailyStats,
      creditStats,
    })
  }
  catch (error) {
    console.error(error)
    res.status(500).send('Error loading analytics')
  }
  finally {
    await db.close()
  }
})

app.listen(3000, () => console.warn('Server is running on http://localhost:3000'))
