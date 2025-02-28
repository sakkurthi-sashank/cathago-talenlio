import type { Database } from 'sqlite'
import fs from 'node:fs'
import path from 'node:path'
import bcrypt from 'bcrypt'
import pdfParse from 'pdf-parse'
import { open } from 'sqlite'
import sqlite3 from 'sqlite3'

export async function initDb(): Promise<Database> {
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

export async function hashPassword(password: string): Promise<string> {
  return await bcrypt.hash(password, 10)
}

export async function comparePassword(password: string, hashedPassword: string): Promise<boolean> {
  return await bcrypt.compare(password, hashedPassword)
}

export function levenshtein(a: string, b: string): number {
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

export function wordFrequency(text: string): Map<string, number> {
  const words = text.toLowerCase().match(/\b[a-z]+\b/gi) || []
  const freqMap = new Map<string, number>()
  words.forEach(word => freqMap.set(word, (freqMap.get(word) || 0) + 1))
  return freqMap
}

export function cosineSimilarity(freq1: Map<string, number>, freq2: Map<string, number>): number {
  const words = new Set([...freq1.keys(), ...freq2.keys()])
  let dotProduct = 0
  let magA = 0
  let magB = 0

  words.forEach((word) => {
    const val1 = freq1.get(word) || 0
    const val2 = freq2.get(word) || 0
    dotProduct += val1 * val2
    magA += val1 * val1
    magB += val2 * val2
  })

  return magA && magB ? dotProduct / (Math.sqrt(magA) * Math.sqrt(magB)) : 0
}

export function calculateSimilarity(text1: string, text2: string): number {
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

export async function extractTextFromFile(file: Express.Multer.File): Promise<string> {
  const filePath = path.resolve(file.path)
  let extractedText = ''

  if (file.mimetype === 'application/pdf') {
    const dataBuffer = fs.readFileSync(filePath)
    const pdfData = await pdfParse(dataBuffer)
    extractedText = pdfData.text
  }
  else if (file.mimetype.startsWith('text/')) {
    extractedText = fs.readFileSync(filePath, 'utf-8')
  }

  return extractedText
}
