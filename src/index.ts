import type { NextFunction, Request, Response } from 'express'
import type { Store } from 'express-session'
import type { Database } from 'sqlite'

import bcrypt from 'bcrypt'
import express from 'express'
import session from 'express-session'
import multer from 'multer'
import pdfParse from 'pdf-parse'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { open } from 'sqlite'
import sqlite3 from 'sqlite3'
import SQLiteStoreFactory from 'connect-sqlite3'

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
      password TEXT NOT NULL
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

  return db
}


async function hashPassword(password: string): Promise<string> {
  return await bcrypt.hash(password, 10)
}

async function comparePassword(password: string, hashedPassword: string): Promise<boolean> {
  return await bcrypt.compare(password, hashedPassword)
}

function isAuthenticated(req: Request, res: Response, next: NextFunction): void {
  if (req.session.user) return next()
  res.redirect('/login')
}

app.get('/login', (req, res) => res.render('login', { message: null, title: 'Login' }))

app.get('/signup', (req, res) => res.render('signup', { message: null, title: 'Sign Up' }))

app.post('/signup', async (req, res) => {
  const { firstname, lastname, email, password, confirmPassword } = req.body
  if (password !== confirmPassword) return res.render('signup', { message: 'Passwords do not match', title: 'Sign Up' })

  const db = await initDb()
  try {
    const hashedPassword = await hashPassword(password)
    await db.run('INSERT INTO users (firstname, lastname, email, password) VALUES (?, ?, ?, ?)', [firstname, lastname, email, hashedPassword])
    res.redirect('/login')
  } catch (error) {
    console.warn(error)
    res.render('signup', { message: 'An error occurred. Email might already be registered.', title: 'Sign Up' })
  } finally {
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
    } else {
      res.render('login', { message: 'Invalid email or password', title: 'Login' })
    }
  } catch (error) {
    console.warn(error)
    res.render('login', { message: 'An error occurred while processing your request. Please try again.', title: 'Login' })
  } finally {
    await db.close()
  }
})

app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error(err)
      res.status(500).send('Error logging out.')
    } else {
      res.redirect('/')
    }
  })
})

app.get('/', isAuthenticated, (req, res) => res.render('layout', { user: req.session.user, title: 'Dashboard', body: 'dashboard' }))

app.post('/upload', isAuthenticated, upload.single('file'), async (req, res) => {
  const file = req.file
  const db = await initDb()

  if (!file) { res.status(400).json({ error: 'No file uploaded.' }); return; }

  let extractedText = ''
  try {
    const filePath = path.resolve(file.path)

    if (file.mimetype === 'application/pdf') {
      const dataBuffer = fs.readFileSync(filePath)
      const pdfData = await pdfParse(dataBuffer)
      extractedText = pdfData.text
    } else if (file.mimetype.startsWith('text/')) {
      extractedText = fs.readFileSync(filePath, 'utf-8')
    } else {
      res.status(400).json({ error: 'Unsupported file type.' })
      return 
    }

    await db.run(
      'INSERT INTO files (user_id, filename, content, mimetype, size) VALUES (?, ?, ?, ?, ?)',
      [req?.session?.user?.id, file.originalname, extractedText, file.mimetype, file.size]
    )

    fs.unlinkSync(filePath)
    res.status(200).json({ message: 'File uploaded and text saved successfully.' })
  } catch (error) {
    console.error(error)
    res.status(500).json({ error: 'Error processing file.' })
  } finally {
    await db.close()
  }
})

app.listen(3000, () => console.warn('Server is running on http://localhost:3000'))
