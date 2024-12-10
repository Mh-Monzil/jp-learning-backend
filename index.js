const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const cors = require('cors');
require('dotenv').config();

const app = express();

// Middleware
app.use(express.json());
app.use(cors());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('MongoDB Connected'))
.catch(err => console.error('MongoDB Connection Error:', err));

// User Schema
const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  photo: { type: String },
  role: { 
    type: String, 
    enum: ['User', 'Admin'], 
    default: 'User' 
  }
});

// Lesson Schema
const LessonSchema = new mongoose.Schema({
  lessonName: { type: String, required: true },
  lessonNumber: { type: Number, required: true, unique: true },
  vocabularyCount: { type: Number, default: 0 }
});

// Vocabulary Schema
const VocabularySchema = new mongoose.Schema({
  word: { type: String, required: true },
  pronunciation: { type: String, required: true },
  meaning: { type: String, required: true },
  whenToSay: { type: String, required: true },
  lessonNo: { type: Number, required: true },
  adminEmail: { type: String, required: true }
});

// Models
const User = mongoose.model('User', UserSchema);
const Lesson = mongoose.model('Lesson', LessonSchema);
const Vocabulary = mongoose.model('Vocabulary', VocabularySchema);

// Multer Configuration for Photo Upload
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});
const upload = multer({ storage: storage });

// Middleware to verify token
const verifyToken = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(401).json({ message: 'No token, authorization denied' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ message: 'Token is not valid' });
  }
};

// Middleware to check admin role
const isAdmin = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);
    if (user.role !== 'Admin') {
      return res.status(403).json({ message: 'Access denied. Admin rights required.' });
    }
    next();
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
};

// Authentication Routes
//Get user
app.get('/api/user', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    res.json(user);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Register
app.post('/api/auth/register', upload.single('photo'), async (req, res) => {
  try {
    const { name, email, password } = req.body;
    
    // Check if user already exists
    let user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create user
    user = new User({
      name,
      email,
      password: hashedPassword,
      photo: req.file ? req.file.path : null
    });

    await user.save();

    // Create token
    const payload = {
      id: user._id,
      name: user.name,
      role: user.role
    };

    const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.status(201).json({ token, user: payload });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check if user exists
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Create token
    const payload = {
      id: user._id,
      name: user.name,
      role: user.role
    };

    const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.json({ token, user: payload });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Lesson Routes
// Create Lesson (Admin only)
app.post('/api/lessons', verifyToken, isAdmin, async (req, res) => {
  try {
    const { lessonName, lessonNumber } = req.body;

    // Check if lesson number already exists
    const existingLesson = await Lesson.findOne({ lessonNumber });
    if (existingLesson) {
      return res.status(400).json({ message: 'Lesson number already exists' });
    }

    const lesson = new Lesson({ lessonName, lessonNumber });
    await lesson.save();

    res.status(201).json(lesson);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get All Lessons
app.get('/api/lessons', verifyToken, async (req, res) => {
  try {
    const lessons = await Lesson.find();
    res.json(lessons);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update Lesson (Admin only)
app.put('/api/lessons/:id', verifyToken, isAdmin, async (req, res) => {
  try {
    const { lessonName, lessonNumber } = req.body;
    const lesson = await Lesson.findByIdAndUpdate(
      req.params.id, 
      { lessonName, lessonNumber }, 
      { new: true }
    );

    if (!lesson) {
      return res.status(404).json({ message: 'Lesson not found' });
    }

    res.json(lesson);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Delete Lesson (Admin only)
app.delete('/api/lessons/:id', verifyToken, isAdmin, async (req, res) => {
  try {
    const lesson = await Lesson.findByIdAndDelete(req.params.id);
    
    if (!lesson) {
      return res.status(404).json({ message: 'Lesson not found' });
    }

    // Delete associated vocabularies
    await Vocabulary.deleteMany({ lessonNo: lesson.lessonNumber });

    res.json({ message: 'Lesson deleted successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Vocabulary Routes
// Create Vocabulary (Admin only)
app.post('/api/vocabularies', verifyToken, isAdmin, async (req, res) => {
  try {
    const { 
      word, 
      pronunciation, 
      meaning, 
      whenToSay, 
      lessonNo 
    } = req.body;

    // Verify lesson exists
    const lesson = await Lesson.findOne({ lessonNumber: lessonNo });
    if (!lesson) {
      return res.status(400).json({ message: 'Lesson does not exist' });
    }

    const vocabulary = new Vocabulary({
      word,
      pronunciation,
      meaning,
      whenToSay,
      lessonNo,
      adminEmail: req.user.email
    });

    await vocabulary.save();

    // Update vocabulary count in lesson
    lesson.vocabularyCount += 1;
    await lesson.save();

    res.status(201).json(vocabulary);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get Vocabularies by Lesson Number
app.get('/api/vocabularies/:lessonNo', verifyToken, async (req, res) => {
  try {
    const vocabularies = await Vocabulary.find({ 
      lessonNo: req.params.lessonNo 
    });

    res.json(vocabularies);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update Vocabulary (Admin only)
app.put('/api/vocabularies/:id', verifyToken, isAdmin, async (req, res) => {
  try {
    const { 
      word, 
      pronunciation, 
      meaning, 
      whenToSay, 
      lessonNo 
    } = req.body;

    const vocabulary = await Vocabulary.findByIdAndUpdate(
      req.params.id, 
      { word, pronunciation, meaning, whenToSay, lessonNo }, 
      { new: true }
    );

    if (!vocabulary) {
      return res.status(404).json({ message: 'Vocabulary not found' });
    }

    res.json(vocabulary);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Delete Vocabulary (Admin only)
app.delete('/api/vocabularies/:id', verifyToken, isAdmin, async (req, res) => {
  try {
    const vocabulary = await Vocabulary.findByIdAndDelete(req.params.id);
    
    if (!vocabulary) {
      return res.status(404).json({ message: 'Vocabulary not found' });
    }

    // Update vocabulary count in lesson
    const lesson = await Lesson.findOne({ lessonNumber: vocabulary.lessonNo });
    if (lesson) {
      lesson.vocabularyCount -= 1;
      await lesson.save();
    }

    res.json({ message: 'Vocabulary deleted successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// User Management Routes
// Get All Users (Admin only)
app.get('/api/users', verifyToken, isAdmin, async (req, res) => {
  try {
    const users = await User.find().select('-password');
    res.json(users);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update User Role (Admin only)
app.put('/api/users/:id/role', verifyToken, isAdmin, async (req, res) => {
  try {
    const { role } = req.body;

    if (!['User', 'Admin'].includes(role)) {
      return res.status(400).json({ message: 'Invalid role' });
    }

    const user = await User.findByIdAndUpdate(
      req.params.id, 
      { role }, 
      { new: true }
    ).select('-password');

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json(user);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get("/", (req, res) => {
    res.send("Welcome to Learning")
})

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));