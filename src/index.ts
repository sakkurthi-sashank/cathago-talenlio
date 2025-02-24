import type { Request, Response } from 'express'
import type { Database } from 'sqlite'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import bcrypt from 'bcrypt'
import express from 'express'
import session from 'express-session'
import { open } from 'sqlite'
import sqlite3 from 'sqlite3'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const app = express()

app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(express.static('public'))

app.use(session({
  secret: 'e334aa515718d7613f52646f0e92a7ff8bd2b2b81bbde28d27698c4a1e9d8fc8',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false },
}))

app.set('view engine', 'ejs')
app.set('views', path.join(__dirname, 'views'))

async function initDb(): Promise<Database> {
  const db = await open({
    filename: 'database.db',
    driver: sqlite3.Database,
  })

  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      firstname TEXT NOT NULL,
      lastname TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
    )
  `)

  return db
}

async function hashPassword(password: string): Promise<string> {
  const saltRounds = 10
  return await bcrypt.hash(password, saltRounds)
}

async function comparePassword(password: string, hashedPassword: string): Promise<boolean> {
  return await bcrypt.compare(password, hashedPassword)
}

app.get('/login', (req: Request, res: Response) => {
  res.render('login', { message: null })
})

app.get('/signup', (req: Request, res: Response) => {
  res.render('signup', { message: null })
})

app.post('/signup', async (req: Request, res: Response) => {
  const { firstname, lastname, email, password, confirmPassword } = req.body

  if (password !== confirmPassword) {
    return res.render('signup', { message: 'Passwords do not match' })
  }

  const db = await initDb()

  try {
    const hashedPassword = await hashPassword(password)
    await db.run('INSERT INTO users (firstname, lastname, email, password) VALUES (?, ?, ?, ?)', [firstname, lastname, email, hashedPassword])
    res.redirect('/login')
  }
  catch (error) {
    console.warn(error)
    res.render('signup', { message: 'An error occurred. Email might already be registered.' })
  }
  finally {
    await db.close()
  }
})

app.post('/login', async (req: Request, res: Response) => {
  const { email, password } = req.body
  const db = await initDb()

  try {
    const user = await db.get('SELECT * FROM users WHERE email = ?', [email])

    if (user && await comparePassword(password, user.password)) {
      req.session.user = { email: user.email, firstname: user.firstname, lastname: user.lastname }
      res.redirect('/')
    }
    else {
      res.render('login', { message: 'Invalid email or password' })
    }
  }
  catch (error) {
    console.warn(error)
    res.render('login', { message: 'An error occurred while processing your request. Please try again.' })
  }
  finally {
    await db.close()
  }
})

app.listen(3000, () => {
  console.warn('Server is running on http://localhost:3000')
})
