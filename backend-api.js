/**
 * Medical Messaging Platform - Backend API
 * 
 * Express.js implementation of the backend API for a secure
 * medical messaging platform.
 */

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const http = require('http');
const socketIo = require('socket.io');
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');

// Initialize express app
const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: process.env.ALLOWED_ORIGINS.split(','),
    methods: ['GET', 'POST'],
    credentials: true
  }
});

// Configuration
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key'; // Use a strong secret in production
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/medical-messaging';
const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB

// Middleware
app.use(helmet()); // Security headers
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS.split(','),
  credentials: true
}));
app.use(morgan('combined')); // Logging
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false
});
app.use('/api/', apiLimiter);

// Connect to MongoDB
mongoose.connect(MONGODB_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// Define schemas
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  passwordHash: { type: String, required: true },
  userType: { type: String, enum: ['patient', 'provider', 'admin'], required: true },
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  phone: { type: String },
  organizationId: { type: String, required: true },
  specialties: [String], // For providers
  patientId: { type: String }, // For patients
  notificationPreferences: {
    email: { type: Boolean, default: true },
    sms: { type: Boolean, default: false },
    inApp: { type: Boolean, default: true }
  },
  lastActive: { type: Date, default: Date.now },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const conversationSchema = new mongoose.Schema({
  participants: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }],
  topic: { type: String, required: true },
  lastMessageAt: { type: Date, default: Date.now },
  metadata: { type: Object, default: {} },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
  organizationId: { type: String, required: true }
});

const messageSchema = new mongoose.Schema({
  conversationId: { type: mongoose.Schema.Types.ObjectId, ref: 'Conversation', required: true },
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  content: { type: String, required: true },
  isEncrypted: { type: Boolean, default: false },
  readBy: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  attachments: [{
    fileId: { type: String },
    fileName: { type: String },
    fileType: { type: String },
    fileSize: { type: Number }
  }],
  metadata: { type: Object, default: {} },
  createdAt: { type: Date, default: Date.now }
});

const fileSchema = new mongoose.Schema({
  originalName: { type: String, required: true },
  encoding: { type: String, required: true },
  mimetype: { type: String, required: true },
  size: { type: Number, required: true },
  filename: { type: String, required: true },
  path: { type: String, required: true },
  uploadedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  conversationId: { type: mongoose.Schema.Types.ObjectId, ref: 'Conversation', required: true },
  organizationId: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const auditLogSchema = new mongoose.Schema({
  action: { type: String, required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  resourceType: { type: String, required: true },
  resourceId: { type: String, required: true },
  details: { type: Object, default: {} },
  ipAddress: { type: String },
  userAgent: { type: String },
  timestamp: { type: Date, default: Date.now },
  organizationId: { type: String, required: true }
});

// Create models
const User = mongoose.model('User', userSchema);
const Conversation = mongoose.model('Conversation', conversationSchema);
const Message = mongoose.model('Message', messageSchema);
const File = mongoose.model('File', fileSchema);
const AuditLog = mongoose.model('AuditLog', auditLogSchema);

// Set up file storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, './uploads/');
  },
  filename: (req, file, cb) => {
    const uniqueFileName = `${Date.now()}-${crypto.randomBytes(16).toString('hex')}${path.extname(file.originalname)}`;
    cb(null, uniqueFileName);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: MAX_FILE_SIZE },
  fileFilter: (req, file, cb) => {
    // Implement file type restrictions here
    const allowedTypes = [
      'image/jpeg', 'image/png', 'image/gif',
      'application/pdf', 'application/msword',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    ];
    
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type'), false);
    }
  }
});

// Authentication middleware
const authenticate = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'Authentication required' });
    }

    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const user = await User.findById(decoded.userId);
    if (!user) {
      return res.status(401).json({ message: 'User not found' });
    }
    
    req.user = user;
    req.organizationId = req.headers['x-organization-id'];
    
    // Log audit entry for sensitive operations
    if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) {
      await logAuditEntry(req);
    }
    
    next();
  } catch (error) {
    console.error('Authentication error:', error);
    res.status(401).json({ message: 'Invalid or expired token' });
  }
};

// Audit logging function
const logAuditEntry = async (req) => {
  try {
    const auditEntry = new AuditLog({
      action: req.method,
      userId: req.user._id,
      resourceType: req.path.split('/')[1],
      resourceId: req.params.id || 'multiple',
      details: {
        path: req.path,
        query: req.query,
        body: req.body
      },
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      organizationId: req.organizationId
    });
    
    await auditEntry.save();
  } catch (error) {
    console.error('Error logging audit entry:', error);
  }
};

// Routes

// Authentication routes
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password, userType } = req.body;
    const organizationId = req.headers['x-organization-id'];
    
    if (!organizationId) {
      return res.status(400).json({ message: 'Organization ID is required' });
    }
    
    const user = await User.findOne({ username, userType, organizationId });
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    
    const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    
    // Create JWT token
    const token = jwt.sign(
      { userId: user._id, userType: user.userType },
      JWT_SECRET,
      { expiresIn: '8h' }
    );
    
    // Update last active
    user.lastActive = new Date();
    await user.save();
    
    // Create audit log
    const auditEntry = new AuditLog({
      action: 'LOGIN',
      userId: user._id,
      resourceType: 'auth',
      resourceId: user._id.toString(),
      details: { userType },
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      organizationId
    });
    
    await auditEntry.save();
    
    // Return user info (without password) and token
    const userResponse = {
      id: user._id,
      username: user.username,
      userType: user.userType,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email
    };
    
    res.json({ user: userResponse, token });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.post('/api/auth/logout', authenticate, async (req, res) => {
  try {
    // Create audit log
    const auditEntry = new AuditLog({
      action: 'LOGOUT',
      userId: req.user._id,
      resourceType: 'auth',
      resourceId: req.user._id.toString(),
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      organizationId: req.organizationId
    });
    
    await auditEntry.save();
    
    // In a real implementation, you might invalidate the token
    // by adding it to a blacklist or using short-lived tokens
    
    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// User routes
app.get('/api/user/profile', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    
    const userProfile = {
      id: user._id,
      username: user.username,
      userType: user.userType,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      phone: user.phone,
      notificationPreferences: user.notificationPreferences,
      lastActive: user.lastActive,
      specialties: user.specialties,
      patientId: user.patientId
    };
    
    res.json(userProfile);
  } catch (error) {
    console.error('Error fetching user profile:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.put('/api/user/notifications', authenticate, async (req, res) => {
  try {
    const { notificationPreferences } = req.body;
    
    const user = await User.findById(req.user._id);
    user.notificationPreferences = notificationPreferences;
    user.updatedAt = new Date();
    
    await user.save();
    
    res.json({ 
      message: 'Notification preferences updated',
      notificationPreferences: user.notificationPreferences
    });
  } catch (error) {
    console.error('Error updating notification preferences:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Conversation routes
app.post('/api/conversations', authenticate, async (req, res) => {
  try {
    const { participants, topic, metadata } = req.body;
    
    // Ensure the current user is included in participants
    if (!participants.includes(req.user._id.toString())) {
      participants.push(req.user._id.toString());
    }
    
    // Convert string IDs to ObjectIds
    const participantIds = participants.map(id => new mongoose.Types.ObjectId(id));
    
    const conversation = new Conversation({
      participants: participantIds,
      topic,
      metadata,
      organizationId: req.organizationId
    });
    
    await conversation.save();
    
    res.status(201).json(conversation);
  } catch (error) {
    console.error('Error creating conversation:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.get('/api/conversations', authenticate, async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    const skip = (page - 1) * limit;
    
    // Get conversations where the user is a participant
    const conversations = await Conversation.find({
      participants: req.user._id,
      organizationId: req.organizationId
    })
      .sort({ lastMessageAt: -1 })
      .skip(skip)
      .limit(parseInt(limit))
      .populate('participants', 'firstName lastName userType');
    
    const totalConversations = await Conversation.countDocuments({
      participants: req.user._id,
      organizationId: req.organizationId
    });
    
    res.json({
      conversations,
      pagination: {
        total: totalConversations,
        page: parseInt(page),
        limit: parseInt(limit),
        pages: Math.ceil(totalConversations / limit)
      }
    });
  } catch (error) {
    console.error('Error fetching conversations:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Message routes
app.post('/api/conversations/:conversationId/messages', authenticate, async (req, res) => {
  try {
    const { conversationId } = req.params;
    const { content, attachments, metadata } = req.body;
    
    // Verify user is part of this conversation
    const conversation = await Conversation.findOne({
      _id: conversationId,
      participants: req.user._id,
      organizationId: req.organizationId
    });
    
    if (!conversation) {
      return res.status(404).json({ message: 'Conversation not found' });
    }
    
    const message = new Message({
      conversationId,
      sender: req.user._id,
      content,
      attachments: attachments || [],
      metadata: metadata || {},
      readBy: [req.user._id] // Sender has read the message
    });
    
    await message.save();
    
    // Update the conversation's lastMessageAt
    conversation.lastMessageAt = new Date();
    await conversation.save();
    
    // Notify other participants via WebSocket
    const messageNotification = {
      type: 'new_message',
      conversationId,
      message: {
        id: message._id,
        sender: {
          id: req.user._id,
          firstName: req.user.firstName,
          lastName: req.user.lastName
        },
        content,
        createdAt: message.createdAt
      }
    };
    
    // Emit to all participants except sender
    conversation.participants.forEach(participantId => {
      if (!participantId.equals(req.user._id)) {
        io.to(participantId.toString()).emit('message', messageNotification);
      }
    });
    
    res.status(201).json(message);
  } catch (error) {
    console.error('Error sending message:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.get('/api/conversations/:conversationId/messages', authenticate, async (req, res) => {
  try {
    const { conversationId } = req.params;
    const { page = 1, limit = 50 } = req.query;
    const skip = (page - 1) * limit;
    
    // Verify user is part of this conversation
    const conversation = await Conversation.findOne({
      _id: conversationId,
      participants: req.user._id,
      organizationId: req.organizationId
    });
    
    if (!conversation) {
      return res.status(404).json({ message: 'Conversation not found' });
    }
    
    const messages = await Message.find({ conversationId })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit))
      .populate('sender', 'firstName lastName userType');
    
    const totalMessages = await Message.countDocuments({ conversationId });
    
    res.json({
      messages,
      pagination: {
        total: totalMessages,
        page: parseInt(page),
        limit: parseInt(limit),
        pages: Math.ceil(totalMessages / limit)
      }
    });
  } catch (error) {
    console.error('Error fetching messages:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.post('/api/conversations/:conversationId/read', authenticate, async (req, res) => {
  try {
    const { conversationId } = req.params;
    const { messageIds } = req.body;
    
    // Verify user is part of this conversation
    const conversation = await Conversation.findOne({
      _id: conversationId,
      participants: req.user._id,
      organizationId: req.organizationId
    });
    
    if (!conversation) {
      return res.status(404).json({ message: 'Conversation not found' });
    }
    
    // Mark messages as read
    await Message.updateMany(
      { 
        _id: { $in: messageIds },
        conversationId,
        readBy: { $ne: req.user._id }
      },
      { $addToSet: { readBy: req.user._id } }
    );
    
    res.json({ message: 'Messages marked as read' });
  } catch (error) {
    console.error('Error marking messages as read:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// File upload route
app.post('/api/files/upload', authenticate, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'No file uploaded' });
    }
    
    const { conversationId } = req.body;
    
    // Verify user is part of this conversation
    const conversation = await Conversation.findOne({
      _id: conversationId,
      participants: req.user._id,
      organizationId: req.organizationId
    });
    
    if (!conversation) {
      return res.status(404).json({ message: 'Conversation not found' });
    }
    
    const file = new File({
      originalName: req.file.originalname,
      encoding: req.file.encoding,
      mimetype: req.file.mimetype,
      size: req.file.size,
      filename: req.file.filename,
      path: req.file.path,
      uploadedBy: req.user._id,
      conversationId,
      organizationId: req.organizationId
    });
    
    await file.save();
    
    res.status(201).json({
      id: file._id,
      originalName: file.originalName,
      mimetype: file.mimetype,
      size: file.size,
      uploadedAt: file.createdAt
    });
  } catch (error) {
    console.error('Error uploading file:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Audit log routes
app.get('/api/audit', authenticate, async (req, res) => {
  try {
    // Check if user is admin
    if (req.user.userType !== 'admin') {
      return res.status(403).json({ message: 'Unauthorized' });
    }
    
    const { page = 1, limit = 100, startDate, endDate, userId, action } = req.query;
    const skip = (page - 1) * limit;
    
    // Build query
    const query = { organizationId: req.organizationId };
    
    if (startDate && endDate) {
      query.timestamp = {
        $gte: new Date(startDate),
        $lte: new Date(endDate)
      };
    }
    
    if (userId) {
      query.userId = userId;
    }
    
    if (action) {
      query.action = action;
    }
    
    const logs = await AuditLog.find(query)
      .sort({ timestamp: -1 })
      .skip(skip)
      .limit(parseInt(limit))
      .populate('userId', 'firstName lastName userType');
    
    const totalLogs = await AuditLog.countDocuments(query);
    
    res.json({
      logs,
      pagination: {
        total: totalLogs,
        page: parseInt(page),
        limit: parseInt(limit),
        pages: Math.ceil(totalLogs / limit)
      }
    });
  } catch (error) {
    console.error('Error fetching audit logs:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// WebSocket handling
io.use(async (socket, next) => {
  try {
    const token = socket.handshake.auth.token || socket.handshake.query.token;
    
    if (!token) {
      return next(new Error('Authentication required'));
    }
    
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId);
    
    if (!user) {
      return next(new Error('User not found'));
    }
    
    socket.user = user;
    next();
  } catch (error) {
    console.error('WebSocket authentication error:', error);
    next(new Error('Authentication error'));
  }
});

io.on('connection', (socket) => {
  console.log(`User connected: ${socket.user.username}`);
  
  // Join a room with the user's ID
  socket.join(socket.user._id.toString());
  
  // Update user status
  User.findByIdAndUpdate(
    socket.user._id,
    { lastActive: new Date() },
    { new: true }
  ).exec();
  
  socket.on('disconnect', () => {
    console.log(`User disconnected: ${socket.user.username}`);
  });
});

// Start server
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;
