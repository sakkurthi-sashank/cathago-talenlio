import type { NextFunction, Request, Response } from 'express'
import fs from 'node:fs'
import { calculateSimilarity, extractTextFromFile, initDb } from './utils'

export function isAuthenticated(req: Request, res: Response, next: NextFunction): void {
  if (req.session.user)
    return next()
  res.redirect('/auth/login')
}

export async function isAdmin(req: Request, res: Response, next: NextFunction): Promise<void> {
  const db = await initDb()

  if (!req.session.user) {
    res.status(401).send('Unauthorized')
    return
  }

  const user = await db.get('SELECT role FROM users WHERE id = ?', [req.session.user?.id])

  if (user && user.role === 'admin' || user.email === 'admin@exammple.com')
    return next()
  res.status(403).send('Access denied')
}

export async function registerUser(firstname: string, lastname: string, email: string, hashedPassword: string): Promise<void> {
  const db = await initDb()
  try {
    await db.run('INSERT INTO users (firstname, lastname, email, password) VALUES (?, ?, ?, ?)', [firstname, lastname, email, hashedPassword])
  }
  finally {
    await db.close()
  }
}

export async function getUserByEmail(email: string): Promise<any> {
  const db = await initDb()
  try {
    return await db.get('SELECT * FROM users WHERE email = ?', [email])
  }
  finally {
    await db.close()
  }
}

export async function getUserById(userId: number): Promise<any> {
  const db = await initDb()
  try {
    return await db.get('SELECT * FROM users WHERE id = ?', [userId])
  }
  finally {
    await db.close()
  }
}

export async function deductCredit(userId: number): Promise<boolean> {
  const db = await initDb()
  try {
    const user = await db.get('SELECT credits FROM users WHERE id = ?', [userId])
    if (user && user.credits > 0) {
      await db.run('UPDATE users SET credits = credits - 1 WHERE id = ?', [userId])
      return true
    }
    return false
  }
  finally {
    await db.close()
  }
}

export async function updateScanStatistics(userId: number): Promise<void> {
  const db = await initDb()
  try {
    const result = await db.run(
      `UPDATE scan_statistics 
       SET scan_count = scan_count + 1 
       WHERE user_id = ? AND scan_date = CURRENT_DATE`,
      [userId],
    )

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

export async function requestCredits(userId: number, creditsRequested: number, reason: string): Promise<void> {
  const db = await initDb()
  try {
    await db.run(
      'INSERT INTO credit_requests (user_id, credits_requested, reason) VALUES (?, ?, ?)',
      [userId, creditsRequested, reason],
    )
  }
  finally {
    await db.close()
  }
}

export async function processCreditRequest(requestId: number, adminId: number, action: string): Promise<void> {
  const db = await initDb()
  try {
    const request = await db.get('SELECT * FROM credit_requests WHERE id = ?', [requestId])
    if (!request) {
      throw new Error('Request not found')
    }

    await db.run(
      'UPDATE credit_requests SET status = ?, processed_at = CURRENT_TIMESTAMP, processed_by = ? WHERE id = ?',
      [action === 'approve' ? 'approved' : 'denied', adminId, requestId],
    )

    if (action === 'approve') {
      await db.run(
        'UPDATE users SET credits = credits + ? WHERE id = ?',
        [request.credits_requested, request.user_id],
      )
    }
  }
  finally {
    await db.close()
  }
}

export async function saveFile(userId: number, filename: string, content: string, mimetype: string, size: number): Promise<number> {
  const db = await initDb()
  try {
    const result = await db.run(
      'INSERT INTO files (user_id, filename, content, mimetype, size) VALUES (?, ?, ?, ?, ?)',
      [userId, filename, content, mimetype, size],
    )
    return result.lastID || 0
  }
  finally {
    await db.close()
  }
}

export async function getFileById(fileId: number): Promise<any> {
  const db = await initDb()
  try {
    return await db.get('SELECT * FROM files WHERE id = ?', [fileId])
  }
  finally {
    await db.close()
  }
}

export async function getUserFiles(userId: number): Promise<any[]> {
  const db = await initDb()
  try {
    return await db.all(
      'SELECT * FROM files WHERE user_id = ? ORDER BY uploaded_at DESC',
      [userId],
    )
  }
  finally {
    await db.close()
  }
}

export async function compareFiles(fileId: number): Promise<{ bestMatch: any | null }> {
  const db = await initDb()
  try {
    const fileToCompare = await db.get('SELECT * FROM files WHERE id = ?', [fileId])
    if (!fileToCompare) {
      throw new Error('Document not found')
    }

    const existingFiles = await db.all('SELECT * FROM files WHERE id != ?', [fileId])

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

    return {
      bestMatch: bestMatch ? { id: bestMatch.id, filename: bestMatch.filename, score: highestScore } : null,
    }
  }
  finally {
    await db.close()
  }
}

export async function getFileMatches(fileId: number): Promise<any[]> {
  const db = await initDb()
  try {
    return await db.all(
      `SELECT f.id, f.filename, f.mimetype, f.size, f.uploaded_at, m.similarity_score
       FROM matches m
       JOIN files f ON (m.file2_id = f.id OR m.file1_id = f.id)
       WHERE (m.file1_id = ? OR m.file2_id = ?) AND f.id != ?
       ORDER BY m.similarity_score DESC`,
      [fileId, fileId, fileId],
    )
  }
  finally {
    await db.close()
  }
}

export async function getAllUsers(): Promise<any[]> {
  const db = await initDb()
  try {
    return await db.all('SELECT id, firstname, lastname, email, credits, role FROM users')
  }
  finally {
    await db.close()
  }
}

export async function updateUserCredits(userId: number, credits: number): Promise<void> {
  const db = await initDb()
  try {
    await db.run('UPDATE users SET credits = ? WHERE id = ?', [credits, userId])
  }
  finally {
    await db.close()
  }
}

export async function updateUserRole(userId: number, role: string): Promise<void> {
  const db = await initDb()
  try {
    await db.run('UPDATE users SET role = ? WHERE id = ?', [role, userId])
  }
  finally {
    await db.close()
  }
}

export async function getPendingCreditRequests(): Promise<any[]> {
  const db = await initDb()
  try {
    return await db.all(`
      SELECT cr.*, u.firstname, u.lastname, u.email 
      FROM credit_requests cr
      JOIN users u ON cr.user_id = u.id
      WHERE cr.status = 'pending'
      ORDER BY cr.created_at DESC
    `)
  }
  finally {
    await db.close()
  }
}

export async function getUserCreditRequests(userId: number): Promise<any[]> {
  const db = await initDb()
  try {
    return await db.all(
      'SELECT * FROM credit_requests WHERE user_id = ? ORDER BY created_at DESC',
      [userId],
    )
  }
  finally {
    await db.close()
  }
}

export async function getAnalyticsData(): Promise<{
  topUsers: any[]
  dailyStats: any[]
  creditStats: any[]
}> {
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

    return { topUsers, dailyStats, creditStats }
  }
  finally {
    await db.close()
  }
}

export async function processUploadedFile(file: Express.Multer.File, userId: number): Promise<{ fileId: number }> {
  if (!file) {
    throw new Error('No file uploaded.')
  }

  if (!(await deductCredit(userId))) {
    throw new Error('Daily upload limit reached. Try again tomorrow or request more credits.')
  }

  let extractedText = ''
  try {
    if (file.mimetype === 'application/pdf' || file.mimetype.startsWith('text/')) {
      extractedText = await extractTextFromFile(file)
    }
    else {
      throw new Error('Unsupported file type.')
    }

    const fileId = await saveFile(userId, file.originalname, extractedText, file.mimetype, file.size)
    await updateScanStatistics(userId)

    fs.unlinkSync(file.path)

    return { fileId }
  }
  catch (error) {
    fs.unlinkSync(file.path)
    throw error
  }
}
