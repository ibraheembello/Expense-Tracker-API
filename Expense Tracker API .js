// Dependencies
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { body, validationResult, query } = require('express-validator');
require('dotenv').config();

const app = express();
app.use(express.json());

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI);

// User Schema
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});

const User = mongoose.model('User', userSchema); // Fixed this line

// Expense Schema
const expenseSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  amount: { type: Number, required: true },
  category: {
    type: String,
    enum: ['Groceries', 'Leisure', 'Electronics', 'Utilities', 'Clothing', 'Health', 'Others'],
    required: true
  },
  date: { type: Date, default: Date.now },
  description: String
});

const Expense = mongoose.model('Expense', expenseSchema);

// Middleware: Auth check
const authMiddleware = async (req, res, next) => {
  try {
    const token = req.header('Authorization').replace('Bearer ', '');
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = { id: decoded.id };
    next();
  } catch (error) {
    res.status(401).json({ error: 'Authentication required' });
  }
};

// Validation middleware
const validate = (validations) => {
  return async (req, res, next) => {
    await Promise.all(validations.map(validation => validation.run(req)));

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  };
};

// Error handling middleware
const errorHandler = (err, req, res, next) => {
  console.error(err.stack);

  if (err instanceof mongoose.Error.ValidationError) {
    return res.status(400).json({ error: 'Validation Error', details: err.errors });
  }

  if (err.name === 'JsonWebTokenError') {
    return res.status(401).json({ error: 'Invalid token' });
  }

  if (err.name === 'TokenExpiredError') {
    return res.status(401).json({ error: 'Token expired' });
  }

  res.status(500).json({ error: 'Internal Server Error' });
};

// Validation rules
const signupValidation = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please enter a valid email'),
  body('password')
    .isLength({ min: 6 })
    .withMessage('Password must be at least 6 characters long')
    .matches(/\d/)
    .withMessage('Password must contain at least one number'),
];

const expenseValidation = [
  body('amount')
    .isFloat({ min: 0.01 })
    .withMessage('Amount must be a positive number'),
  body('category')
    .isIn(['Groceries', 'Leisure', 'Electronics', 'Utilities', 'Clothing', 'Health', 'Others'])
    .withMessage('Invalid category'),
  body('description')
    .optional()
    .trim()
    .isLength({ min: 1, max: 500 })
    .withMessage('Description must be between 1 and 500 characters'),
];

const dateFilterValidation = [
  query('filter')
    .optional()
    .isIn(['week', 'month', 'threemonths', 'custom'])
    .withMessage('Invalid filter type'),
  query('startDate')
    .optional()
    .isISO8601()
    .withMessage('Invalid start date format'),
  query('endDate')
    .optional()
    .isISO8601()
    .withMessage('Invalid end date format'),
];

// Auth Routes
app.post('/signup', validate(signupValidation), async (req, res, next) => {
  try {
    const { email, password } = req.body;
    
    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    const hashedPassword = await bcrypt.hash(password, 8);
    const user = new User({ email, password: hashedPassword });
    await user.save();
    
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '24h' });
    res.status(201).json({ token });
  } catch (error) {
    next(error);
  }
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      throw new Error('Invalid credentials');
    }
    
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
    res.json({ token });
  } catch (error) {
    res.status(401).json({ error: error.message });
  }
});

// Expense Routes
app.post('/expenses', 
  authMiddleware, 
  validate(expenseValidation),
  async (req, res, next) => {
    try {
      const expense = new Expense({
        ...req.body,
        userId: req.user.id
      });
      await expense.save();
      res.status(201).json(expense);
    } catch (error) {
      next(error);
    }
});

app.get('/expenses',
  authMiddleware,
  validate(dateFilterValidation),
  async (req, res, next) => {
    try {
      const { filter, startDate, endDate } = req.query;
      let dateFilter = { userId: req.user.id };

      if (filter === 'custom' && (!startDate || !endDate)) {
        return res.status(400).json({ 
          error: 'Both startDate and endDate are required for custom filter' 
        });
      }

      if (filter || startDate) {
        const now = new Date();
        switch (filter) {
          case 'week':
            dateFilter.date = { $gte: new Date(now - 7 * 24 * 60 * 60 * 1000) };
            break;
          case 'month':
            dateFilter.date = { $gte: new Date(now - 30 * 24 * 60 * 60 * 1000) };
            break;
          case 'threemonths':
            dateFilter.date = { $gte: new Date(now - 90 * 24 * 60 * 60 * 1000) };
            break;
          case 'custom':
            dateFilter.date = {
              $gte: new Date(startDate),
              $lte: new Date(endDate)
            };
            break;
        }
      }

      const expenses = await Expense.find(dateFilter);
      res.json(expenses);
    } catch (error) {
      next(error);
    }
});

app.put('/expenses/:id', 
  authMiddleware,
  validate(expenseValidation),
  async (req, res, next) => {
    try {
      const expense = await Expense.findOneAndUpdate(
        { _id: req.params.id, userId: req.user.id },
        req.body,
        { new: true, runValidators: true }
      );
      if (!expense) {
        return res.status(404).json({ error: 'Expense not found' });
      }
      res.json(expense);
    } catch (error) {
      next(error);
    }
});

app.delete('/expenses/:id', authMiddleware, async (req, res) => {
  try {
    const expense = await Expense.findOneAndDelete({
      _id: req.params.id,
      userId: req.user.id
    });
    if (!expense) {
      return res.status(404).json({ error: 'Expense not found' });
    }
    res.json({ message: 'Expense deleted' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Add error handling middleware at the end
app.use(errorHandler);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));