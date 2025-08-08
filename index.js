const express = require('express')
const { MongoClient, ObjectId } = require('mongodb')
const cors = require('cors')
const jwt = require('jsonwebtoken')
const helmet = require('helmet')
require('dotenv').config()

if (process.env.MONGODB_URI && process.env.MONGODB_URI.includes('${')) {
  process.env.MONGODB_URI = process.env.MONGODB_URI
    .replace('${DB_USER}', process.env.DB_USER)
    .replace('${DB_PASS}', process.env.DB_PASS)
}

function assertEnv(name) {
  if (!process.env[name] || String(process.env[name]).trim() === '') {
    console.error(`Missing required environment variable: ${name}`)
    process.exit(1)
  }
}

assertEnv('MONGODB_URI')
assertEnv('DB_NAME')
assertEnv('JWT_SECRET')
assertEnv('CLIENT_URL')

const app = express()
const port = Number(process.env.PORT || 5000)

app.use(express.json({ limit: '1mb' }))
app.use(helmet({
  crossOriginEmbedderPolicy: false,
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "https://b11-a11-frontend.vercel.app"]
    }
  }
}))
app.use(
  cors({
    origin: [
      'http://localhost:5173',
      'http://localhost:5174',
      'http://localhost:5175',
      'http://localhost:5176',
      'https://b11-a11-frontend.vercel.app',
      process.env.CLIENT_URL
    ].filter(Boolean),
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
    optionsSuccessStatus: 200
  })
)

const uri = process.env.MONGODB_URI
const client = new MongoClient(uri)
const dbName = process.env.DB_NAME

let queriesCollection
let recommendationsCollection

function isValidUrl(url) {
  const pattern = /^(https?:\/\/)[\w.-]+\.[a-z]{2,}(\/[^\s]*)?$/i
  return pattern.test(url)
}

async function connectToMongoDB() {
  try {
    await client.connect()
    const db = client.db(dbName)
    queriesCollection = db.collection('queries')
    recommendationsCollection = db.collection('recommendations')
    await queriesCollection.createIndex({ productName: 'text' })
    await queriesCollection.createIndex({ createdAt: -1 })
    await recommendationsCollection.createIndex({ queryId: 1 })
    await recommendationsCollection.createIndex({ createdAt: -1 })
  } catch (error) {
    console.error('MongoDB connection error', error)
    process.exit(1)
  }
}

const verifyJWT = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        message: 'Unauthorized access',
        error: 'No valid authorization header provided'
      })
    }

    const token = authHeader.split(' ')[1]
    if (!token) {
      return res.status(401).json({
        message: 'Unauthorized access',
        error: 'No token provided'
      })
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
      if (err) {
        console.error('JWT verification error:', err.message)
        return res.status(403).json({
          message: 'Forbidden access',
          error: 'Invalid or expired token'
        })
      }
      req.user = decoded
      next()
    })
  } catch (error) {
    console.error('JWT middleware error:', error)
    return res.status(500).json({
      message: 'Internal server error',
      error: 'Token verification failed'
    })
  }
}

app.get('/health', (req, res) => {
  res.json({ status: 'ok' })
})

app.post('/auth/jwt', async (req, res) => {
  try {
    const { email } = req.body || {}

    // Validate email format
    if (!email || typeof email !== 'string') {
      return res.status(400).json({
        message: 'Email is required',
        error: 'Invalid email format'
      })
    }

    // Basic email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    if (!emailRegex.test(email)) {
      return res.status(400).json({
        message: 'Invalid email format',
        error: 'Please provide a valid email address'
      })
    }

    // Create JWT token with additional claims
    const token = jwt.sign(
      {
        email: email.toLowerCase().trim(),
        iat: Math.floor(Date.now() / 1000),
        iss: 'b11-a11-backend'
      },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    )

    res.json({
      token,
      expiresIn: '7d',
      user: { email: email.toLowerCase().trim() }
    })
  } catch (error) {
    console.error('JWT creation error:', error)
    res.status(500).json({
      message: 'Internal server error',
      error: 'Failed to create authentication token'
    })
  }
})

app.get('/queries', async (req, res) => {
  try {
    const { search } = req.query
    const filter = search
      ? { productName: { $regex: String(search), $options: 'i' } }
      : {}
    const queries = await queriesCollection.find(filter).sort({ createdAt: -1 }).toArray()
    res.json(queries)
  } catch (error) {
    res.status(500).json({ message: 'Internal server error' })
  }
})

app.get('/queries/:id', async (req, res) => {
  try {
    const { id } = req.params
    if (!ObjectId.isValid(id)) return res.status(400).json({ message: 'Invalid ID format' })
    const query = await queriesCollection.findOne({ _id: new ObjectId(id) })
    if (!query) return res.status(404).json({ message: 'Query not found' })
    res.json(query)
  } catch (error) {
    res.status(500).json({ message: 'Internal server error' })
  }
})

app.post('/queries', verifyJWT, async (req, res) => {
  try {
    const { productName, productBrand, productImage, queryTitle, boycottReason, userName, userPhoto } = req.body || {}
    if (!productName || !productBrand || !productImage || !queryTitle || !boycottReason) {
      return res.status(400).json({ message: 'All fields are required' })
    }
    if (!isValidUrl(productImage)) {
      return res.status(400).json({ message: 'Invalid image URL' })
    }
    const newQuery = {
      productName,
      productBrand,
      productImage,
      queryTitle,
      boycottReason,
      userEmail: req.user.email,
      userName: userName || '',
      userPhoto: userPhoto || '',
      createdAt: new Date().toISOString(),
      recommendationCount: 0,
    }
    const result = await queriesCollection.insertOne(newQuery)
    res.status(201).json({ _id: result.insertedId, ...newQuery })
  } catch (error) {
    res.status(500).json({ message: 'Internal server error' })
  }
})

app.put('/queries/:id', verifyJWT, async (req, res) => {
  try {
    const { id } = req.params
    const { productName, productBrand, productImage, queryTitle, boycottReason } = req.body || {}
    if (!ObjectId.isValid(id)) return res.status(400).json({ message: 'Invalid ID format' })
    const existingQuery = await queriesCollection.findOne({ _id: new ObjectId(id) })
    if (!existingQuery) return res.status(404).json({ message: 'Query not found' })
    if (existingQuery.userEmail !== req.user.email) {
      return res.status(403).json({ message: 'Unauthorized to update this query' })
    }
    if (productImage && !isValidUrl(productImage)) {
      return res.status(400).json({ message: 'Invalid image URL' })
    }
    const updatedQuery = {
      $set: { productName, productBrand, productImage, queryTitle, boycottReason },
    }
    await queriesCollection.updateOne({ _id: new ObjectId(id) }, updatedQuery)
    res.json({ message: 'Query updated successfully' })
  } catch (error) {
    res.status(500).json({ message: 'Internal server error' })
  }
})

app.delete('/queries/:id', verifyJWT, async (req, res) => {
  try {
    const { id } = req.params
    if (!ObjectId.isValid(id)) return res.status(400).json({ message: 'Invalid ID format' })
    const existingQuery = await queriesCollection.findOne({ _id: new ObjectId(id) })
    if (!existingQuery) return res.status(404).json({ message: 'Query not found' })
    if (existingQuery.userEmail !== req.user.email) {
      return res.status(403).json({ message: 'Unauthorized to delete this query' })
    }
    await queriesCollection.deleteOne({ _id: new ObjectId(id) })
    await recommendationsCollection.deleteMany({ queryId: id })
    res.json({ message: 'Query and related recommendations deleted successfully' })
  } catch (error) {
    res.status(500).json({ message: 'Internal server error' })
  }
})

app.get('/recommendations/by-query/:queryId', async (req, res) => {
  try {
    const { queryId } = req.params
    if (!ObjectId.isValid(queryId)) return res.status(400).json({ message: 'Invalid query ID format' })
    const recommendations = await recommendationsCollection
      .find({ queryId })
      .sort({ createdAt: -1 })
      .toArray()
    res.json(recommendations)
  } catch (error) {
    res.status(500).json({ message: 'Internal server error' })
  }
})

app.get('/recommendations/my', verifyJWT, async (req, res) => {
  try {
    const recommendations = await recommendationsCollection
      .find({ recommenderEmail: req.user.email })
      .sort({ createdAt: -1 })
      .toArray()
    res.json(recommendations)
  } catch (error) {
    res.status(500).json({ message: 'Internal server error' })
  }
})

app.get('/recommendations/for-me', verifyJWT, async (req, res) => {
  try {
    const recommendations = await recommendationsCollection
      .find({ userEmail: req.user.email, recommenderEmail: { $ne: req.user.email } })
      .sort({ createdAt: -1 })
      .toArray()
    res.json(recommendations)
  } catch (error) {
    res.status(500).json({ message: 'Internal server error' })
  }
})

app.post('/recommendations', verifyJWT, async (req, res) => {
  try {
    const {
      queryId,
      queryTitle,
      productName,
      userEmail,
      userName,
      recommendedTitle,
      recommendedProductName,
      recommendedProductImage,
      recommendationReason,
      recommenderName,
    } = req.body || {}
    if (!ObjectId.isValid(queryId)) return res.status(400).json({ message: 'Invalid query ID format' })
    if (!queryId || !queryTitle || !productName || !userEmail || !recommendedTitle || !recommendedProductName || !recommendedProductImage || !recommendationReason) {
      return res.status(400).json({ message: 'All fields are required' })
    }
    if (!isValidUrl(recommendedProductImage)) {
      return res.status(400).json({ message: 'Invalid image URL' })
    }
    const newRecommendation = {
      queryId,
      queryTitle,
      productName,
      userEmail,
      userName,
      recommenderEmail: req.user.email,
      recommenderName: recommenderName || '',
      recommendedTitle,
      recommendedProductName,
      recommendedProductImage,
      recommendationReason,
      createdAt: new Date().toISOString(),
    }
    const result = await recommendationsCollection.insertOne(newRecommendation)
    await queriesCollection.updateOne({ _id: new ObjectId(queryId) }, { $inc: { recommendationCount: 1 } })
    res.status(201).json({ _id: result.insertedId, ...newRecommendation })
  } catch (error) {
    res.status(500).json({ message: 'Internal server error' })
  }
})

app.delete('/recommendations/:id', verifyJWT, async (req, res) => {
  try {
    const { id } = req.params
    if (!ObjectId.isValid(id)) return res.status(400).json({ message: 'Invalid ID format' })
    const existingRecommendation = await recommendationsCollection.findOne({ _id: new ObjectId(id) })
    if (!existingRecommendation) return res.status(404).json({ message: 'Recommendation not found' })
    if (existingRecommendation.recommenderEmail !== req.user.email) {
      return res.status(403).json({ message: 'Unauthorized to delete this recommendation' })
    }
    await recommendationsCollection.deleteOne({ _id: new ObjectId(id) })
    if (existingRecommendation.queryId) {
      await queriesCollection.updateOne(
        { _id: new ObjectId(existingRecommendation.queryId) },
        { $inc: { recommendationCount: -1 } }
      )
    }
    res.json({ message: 'Recommendation deleted successfully' })
  } catch (error) {
    res.status(500).json({ message: 'Internal server error' })
  }
})

app.use('*', (req, res) => {
  res.status(404).json({ message: 'Route not found' })
})

app.use((err, req, res, next) => {
  res.status(500).json({ message: 'Internal server error' })
})

async function startServer() {
  try {
    await connectToMongoDB()
    app.listen(port, () => {
      console.log(`Server running on port ${port}`)
    })
  } catch (error) {
    console.error('Failed to start server', error)
    process.exit(1)
  }
}

startServer()

process.on('SIGINT', async () => {
  try {
    await client.close()
    process.exit(0)
  } catch (error) {
    process.exit(1)
  }
})

