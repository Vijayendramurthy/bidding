const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Connection
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://vijayendramurthy671:<db_password>@ebidding.hvtoacf.mongodb.net/bidapp2?retryWrites=true&w=majority&appName=ebidding';

console.log('Connecting to MongoDB with URI:', MONGODB_URI.replace(/\/\/[^:]+:[^@]+@/, '//***:***@')); // Hide credentials in logs

mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('✅ Connected to MongoDB Atlas - ebidding database'))
.catch(err => {
  console.error('❌ MongoDB connection error:', err.message);
  console.error('Please check:');
  console.error('1. Username and password are correct in MongoDB Atlas');
  console.error('2. Your IP address is whitelisted in Network Access');
  console.error('3. Database user has proper permissions');
});

// User Schema
const userSchema = new mongoose.Schema({
  fullName: {
    type: String,
    required: true,
    trim: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },
  password: {
    type: String,
    required: true,
    minlength: 6
  },
  phone: {
    type: String,
    trim: true
  },
  profileImage: {
    type: String,
    default: ''
  },
  isActive: {
    type: Boolean,
    default: true
  },
  totalBids: {
    type: Number,
    default: 0
  },
  wonBids: {
    type: Number,
    default: 0
  }
}, {
  timestamps: true
});

// Bid Schema
const bidSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
    trim: true
  },
  description: {
    type: String,
    required: true
  },
  startingPrice: {
    type: Number,
    required: true,
    min: 0
  },
  currentPrice: {
    type: Number,
    required: true,
    min: 0
  },
  buyNowPrice: {
    type: Number,
    min: 0
  },
  images: [{
    type: String
  }],
  category: {
    type: String,
    required: true
  },
  condition: {
    type: String,
    enum: ['new', 'like-new', 'good', 'fair', 'poor'],
    default: 'good'
  },
  seller: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  currentBidder: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  bidders: [{
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    amount: {
      type: Number,
      required: true
    },
    timestamp: {
      type: Date,
      default: Date.now
    }
  }],
  startTime: {
    type: Date,
    required: true
  },
  endTime: {
    type: Date,
    required: true
  },
  status: {
    type: String,
    enum: ['active', 'completed', 'cancelled'],
    default: 'active'
  },
  winner: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  minBidIncrement: {
    type: Number,
    default: 10
  }
}, {
  timestamps: true
});

const User = mongoose.model('User', userSchema);
const Bid = mongoose.model('Bid', bidSchema);

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  console.log('Auth header:', authHeader);
  console.log('Token exists:', !!token);

  if (!token) {
    console.log('No token provided');
    return res.status(401).json({ message: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.log('JWT verification error:', err.message);
      return res.status(403).json({ message: 'Invalid or expired token' });
    }
    console.log('JWT verified successfully for user:', user.userId);
    req.user = user;
    next();
  });
};

// Authentication Routes

// Register
app.post('/auth/register', async (req, res) => {
  try {
    const { fullName, email, password, phone } = req.body;

    // Validate required fields
    if (!fullName || !email || !password) {
      return res.status(400).json({ message: 'Please provide all required fields' });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists with this email' });
    }

    // Hash password
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create new user
    const newUser = new User({
      fullName,
      email,
      password: hashedPassword,
      phone: phone || ''
    });

    await newUser.save();

    // Generate JWT token
    const token = jwt.sign(
      { userId: newUser._id, email: newUser.email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: {
        id: newUser._id,
        fullName: newUser.fullName,
        email: newUser.email,
        phone: newUser.phone,
        totalBids: newUser.totalBids,
        wonBids: newUser.wonBids
      }
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Server error during registration' });
  }
});

// Login
app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate required fields
    if (!email || !password) {
      return res.status(400).json({ message: 'Please provide email and password' });
    }

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Check password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id, email: user.email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        fullName: user.fullName,
        email: user.email,
        phone: user.phone,
        totalBids: user.totalBids,
        wonBids: user.wonBids
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error during login' });
  }
});

// Bid Routes

// Get all bids with optional filtering
app.get('/bids', async (req, res) => {
  try {
    const { status, category, limit, offset, search } = req.query;
    
    // Build filter object
    let filter = {};
    
    if (status) {
      filter.status = status;
    }
    
    if (category && category !== 'all') {
      filter.category = category;
    }
    
    if (search) {
      filter.$or = [
        { title: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } }
      ];
    }
    
    // Set pagination
    const limitNum = parseInt(limit) || 20;
    const offsetNum = parseInt(offset) || 0;
    
    // Fetch bids with population
    const bids = await Bid.find(filter)
      .populate('seller', 'fullName email')
      .populate('currentBidder', 'fullName')
      .sort({ createdAt: -1 })
      .limit(limitNum)
      .skip(offsetNum);
    
    // Get total count for pagination
    const totalCount = await Bid.countDocuments(filter);
    
    res.json({
      bids,
      totalCount,
      hasMore: offsetNum + limitNum < totalCount
    });

  } catch (error) {
    console.error('Error fetching bids:', error);
    res.status(500).json({ message: 'Server error fetching bids' });
  }
});

// Get single bid
app.get('/bids/:id', async (req, res) => {
  try {
    const bid = await Bid.findById(req.params.id)
      .populate('seller', 'fullName email phone')
      .populate('currentBidder', 'fullName')
      .populate('bidders.user', 'fullName');

    if (!bid) {
      return res.status(404).json({ message: 'Bid not found' });
    }

    res.json(bid);

  } catch (error) {
    console.error('Error fetching bid:', error);
    res.status(500).json({ message: 'Server error fetching bid' });
  }
});

// Create new bid
app.post('/bids', authenticateToken, async (req, res) => {
  try {
    const {
      title,
      description,
      startingPrice,
      buyNowPrice,
      category,
      condition,
      images,
      duration = 7, // days
      minBidIncrement
    } = req.body;

    // Validate required fields
    if (!title || !description || !startingPrice || !category) {
      return res.status(400).json({ message: 'Please provide all required fields' });
    }

    const startTime = new Date();
    const endTime = new Date();
    endTime.setDate(endTime.getDate() + duration);

    const newBid = new Bid({
      title,
      description,
      startingPrice,
      currentPrice: startingPrice,
      buyNowPrice,
      category,
      condition,
      images: images || [],
      seller: req.user.userId,
      startTime,
      endTime,
      minBidIncrement: minBidIncrement || 10
    });

    await newBid.save();
    await newBid.populate('seller', 'fullName email');

    res.status(201).json({
      message: 'Bid created successfully',
      bid: newBid
    });

  } catch (error) {
    console.error('Error creating bid:', error);
    res.status(500).json({ message: 'Server error creating bid' });
  }
});

// Place a bid
app.post('/bids/:id/place-bid', authenticateToken, async (req, res) => {
  try {
    console.log('Place bid request received for user:', req.user.userId);
    const { amount } = req.body;
    const bidId = req.params.id;
    const userId = req.user.userId;

    console.log('Bid amount:', amount, 'Bid ID:', bidId, 'User ID:', userId);

    const bid = await Bid.findById(bidId);
    if (!bid) {
      return res.status(404).json({ message: 'Bid not found' });
    }

    // Check if bid is still active
    if (bid.status !== 'active' || new Date() > bid.endTime) {
      return res.status(400).json({ message: 'Bid is no longer active' });
    }

    // Check if user is not the seller
    if (bid.seller.toString() === userId) {
      return res.status(400).json({ message: 'You cannot bid on your own item' });
    }

    // Validate bid amount
    const minBidAmount = bid.currentPrice + bid.minBidIncrement;
    if (amount < minBidAmount) {
      return res.status(400).json({ 
        message: `Bid must be at least $${minBidAmount}` 
      });
    }

    // Update bid
    bid.currentPrice = amount;
    bid.currentBidder = userId;
    bid.bidders.push({
      user: userId,
      amount: amount,
      timestamp: new Date()
    });

    await bid.save();

    // Update user's total bids
    await User.findByIdAndUpdate(userId, { $inc: { totalBids: 1 } });

    res.json({
      message: 'Bid placed successfully',
      currentPrice: bid.currentPrice
    });

  } catch (error) {
    console.error('Error placing bid:', error);
    res.status(500).json({ message: 'Server error placing bid' });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    message: 'Bidding App Server is running!', 
    timestamp: new Date().toISOString(),
    database: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected'
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Something went wrong!' });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
  console.log(`Health check: http://localhost:${PORT}/health`);
});

module.exports = app;
