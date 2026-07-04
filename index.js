require('dotenv').config();
const express = require('express');
const { body, validationResult } = require('express-validator');
const db = require('./db');
const { hashPassword, comparePassword, generateToken, authMiddleware } = require('./auth');

const app = express();
const PORT = process.env.PORT || 3001;

app.use(express.json());

function handleValidationErrors(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array().map(e => e.msg) });
  }
  next();
}

const signupValidation = [
  body('name').trim().notEmpty().withMessage('Name is required'),
  body('email').trim().isEmail().withMessage('Valid email is required').normalizeEmail(),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
];

app.post('/signup', signupValidation, handleValidationErrors, async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const existing = await db.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existing.rows.length > 0) {
      return res.status(409).json({ error: 'An account with this email already exists' });
    }

    const passwordHash = await hashPassword(password);
    const result = await db.query(
      'INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id, name, email, created_at',
      [name, email, passwordHash]
    );

    const user = result.rows[0];
    const token = generateToken(user.id);

    res.status(201).json({ user, token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

const loginValidation = [
  body('email').trim().isEmail().withMessage('Valid email is required').normalizeEmail(),
  body('password').notEmpty().withMessage('Password is required')
];

app.post('/login', loginValidation, handleValidationErrors, async (req, res) => {
  try {
    const { email, password } = req.body;

    const result = await db.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const user = result.rows[0];
    const validPassword = await comparePassword(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const token = generateToken(user.id);
    res.json({
      user: { id: user.id, name: user.name, email: user.email, created_at: user.created_at },
      token
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/me', authMiddleware, async (req, res) => {
  try {
    const result = await db.query('SELECT id, name, email, created_at FROM users WHERE id = $1', [req.userId]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

const orgValidation = [
  body('name').trim().notEmpty().withMessage('Organization name is required')
];

app.post('/organizations', authMiddleware, orgValidation, handleValidationErrors, async (req, res) => {
  try {
    const { name } = req.body;

    const orgResult = await db.query(
      'INSERT INTO organizations (name, created_by) VALUES ($1, $2) RETURNING *',
      [name, req.userId]
    );
    const org = orgResult.rows[0];

    await db.query(
      'INSERT INTO organization_members (organization_id, user_id, role) VALUES ($1, $2, $3)',
      [org.id, req.userId, 'owner']
    );

    res.status(201).json(org);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/organizations', authMiddleware, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT o.*, om.role FROM organizations o
       JOIN organization_members om ON om.organization_id = o.id
       WHERE om.user_id = $1
       ORDER BY o.created_at DESC`,
      [req.userId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/organizations/:id', authMiddleware, async (req, res) => {
  try {
    const membership = await db.query(
      'SELECT * FROM organization_members WHERE organization_id = $1 AND user_id = $2',
      [req.params.id, req.userId]
    );
    if (membership.rows.length === 0) {
      return res.status(403).json({ error: 'You are not a member of this organization' });
    }

    const orgResult = await db.query('SELECT * FROM organizations WHERE id = $1', [req.params.id]);
    if (orgResult.rows.length === 0) {
      return res.status(404).json({ error: 'Organization not found' });
    }

    const membersResult = await db.query(
      `SELECT u.id, u.name, u.email, om.role FROM organization_members om
       JOIN users u ON u.id = om.user_id
       WHERE om.organization_id = $1`,
      [req.params.id]
    );

    res.json({ ...orgResult.rows[0], members: membersResult.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

const inviteValidation = [
  body('email').trim().isEmail().withMessage('Valid email is required').normalizeEmail()
];

app.post('/organizations/:id/invite', authMiddleware, inviteValidation, handleValidationErrors, async (req, res) => {
  try {
    const membership = await db.query(
      'SELECT role FROM organization_members WHERE organization_id = $1 AND user_id = $2',
      [req.params.id, req.userId]
    );
    if (membership.rows.length === 0) {
      return res.status(403).json({ error: 'You are not a member of this organization' });
    }
    if (membership.rows[0].role !== 'owner') {
      return res.status(403).json({ error: 'Only the owner can invite members' });
    }

    const { email } = req.body;
    const userResult = await db.query('SELECT id FROM users WHERE email = $1', [email]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'No user found with that email. They need to sign up first.' });
    }

    const invitedUserId = userResult.rows[0].id;

    const existing = await db.query(
      'SELECT id FROM organization_members WHERE organization_id = $1 AND user_id = $2',
      [req.params.id, invitedUserId]
    );
    if (existing.rows.length > 0) {
      return res.status(409).json({ error: 'This user is already a member' });
    }

    await db.query(
      'INSERT INTO organization_members (organization_id, user_id, role) VALUES ($1, $2, $3)',
      [req.params.id, invitedUserId, 'member']
    );

    res.status(201).json({ message: 'User added to organization' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

const expenseValidation = [
  body('description').trim().notEmpty().withMessage('Description is required'),
  body('amount').isFloat({ gt: 0 }).withMessage('Amount must be a positive number')
];

app.post('/organizations/:id/expenses', authMiddleware, expenseValidation, handleValidationErrors, async (req, res) => {
  try {
    const membership = await db.query(
      'SELECT * FROM organization_members WHERE organization_id = $1 AND user_id = $2',
      [req.params.id, req.userId]
    );
    if (membership.rows.length === 0) {
      return res.status(403).json({ error: 'You are not a member of this organization' });
    }

    const { description, amount } = req.body;

    const membersResult = await db.query(
      'SELECT user_id FROM organization_members WHERE organization_id = $1',
      [req.params.id]
    );
    const members = membersResult.rows;

    if (members.length === 0) {
      return res.status(400).json({ error: 'No members to split this expense between' });
    }

    const expenseResult = await db.query(
      'INSERT INTO expenses (organization_id, description, amount, paid_by) VALUES ($1, $2, $3, $4) RETURNING *',
      [req.params.id, description, amount, req.userId]
    );
    const expense = expenseResult.rows[0];

    const splitAmount = (parseFloat(amount) / members.length).toFixed(2);

    for (const member of members) {
      await db.query(
        'INSERT INTO expense_splits (expense_id, user_id, amount_owed) VALUES ($1, $2, $3)',
        [expense.id, member.user_id, splitAmount]
      );
    }

    res.status(201).json({ ...expense, split_between: members.length, amount_per_person: splitAmount });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/organizations/:id/expenses', authMiddleware, async (req, res) => {
  try {
    const membership = await db.query(
      'SELECT * FROM organization_members WHERE organization_id = $1 AND user_id = $2',
      [req.params.id, req.userId]
    );
    if (membership.rows.length === 0) {
      return res.status(403).json({ error: 'You are not a member of this organization' });
    }

    const result = await db.query(
      `SELECT e.*, u.name as paid_by_name FROM expenses e
       JOIN users u ON u.id = e.paid_by
       WHERE e.organization_id = $1
       ORDER BY e.created_at DESC`,
      [req.params.id]
    );

    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/organizations/:id/balances', authMiddleware, async (req, res) => {
  try {
    const membership = await db.query(
      'SELECT * FROM organization_members WHERE organization_id = $1 AND user_id = $2',
      [req.params.id, req.userId]
    );
    if (membership.rows.length === 0) {
      return res.status(403).json({ error: 'You are not a member of this organization' });
    }

    const paidResult = await db.query(
      `SELECT paid_by as user_id, SUM(amount) as total_paid
       FROM expenses WHERE organization_id = $1
       GROUP BY paid_by`,
      [req.params.id]
    );

    const owedResult = await db.query(
      `SELECT es.user_id, SUM(es.amount_owed) as total_owed
       FROM expense_splits es
       JOIN expenses e ON e.id = es.expense_id
       WHERE e.organization_id = $1
       GROUP BY es.user_id`,
      [req.params.id]
    );

    const membersResult = await db.query(
      `SELECT u.id, u.name FROM organization_members om
       JOIN users u ON u.id = om.user_id
       WHERE om.organization_id = $1`,
      [req.params.id]
    );

    const paidMap = Object.fromEntries(paidResult.rows.map(r => [r.user_id, parseFloat(r.total_paid)]));
    const owedMap = Object.fromEntries(owedResult.rows.map(r => [r.user_id, parseFloat(r.total_owed)]));

    const balances = membersResult.rows.map(member => {
      const paid = paidMap[member.id] || 0;
      const owed = owedMap[member.id] || 0;
      const balance = paid - owed;
      return {
        user_id: member.id,
        name: member.name,
        total_paid: paid.toFixed(2),
        total_owed: owed.toFixed(2),
        balance: balance.toFixed(2),
        status: balance > 0 ? 'is owed money' : balance < 0 ? 'owes money' : 'settled up'
      };
    });

    res.json(balances);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});










app.put('/organizations/:id/expenses/:expenseId', authMiddleware, expenseValidation, handleValidationErrors, async (req, res) => {
  try {
    const membership = await db.query(
      'SELECT * FROM organization_members WHERE organization_id = $1 AND user_id = $2',
      [req.params.id, req.userId]
    );
    if (membership.rows.length === 0) {
      return res.status(403).json({ error: 'You are not a member of this organization' });
    }

    const { description, amount } = req.body;

    const membersResult = await db.query(
      'SELECT user_id FROM organization_members WHERE organization_id = $1',
      [req.params.id]
    );
    const members = membersResult.rows;

    const updateResult = await db.query(
      'UPDATE expenses SET description = $1, amount = $2 WHERE id = $3 AND organization_id = $4 RETURNING *',
      [description, amount, req.params.expenseId, req.params.id]
    );

    if (updateResult.rows.length === 0) {
      return res.status(404).json({ error: 'Expense not found' });
    }

    const expense = updateResult.rows[0];

    await db.query('DELETE FROM expense_splits WHERE expense_id = $1', [req.params.expenseId]);

    const splitAmount = (parseFloat(amount) / members.length).toFixed(2);
    for (const member of members) {
      await db.query(
        'INSERT INTO expense_splits (expense_id, user_id, amount_owed) VALUES ($1, $2, $3)',
        [expense.id, member.user_id, splitAmount]
      );
    }

    res.json({ ...expense, split_between: members.length, amount_per_person: splitAmount });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/organizations/:id/members/:userId', authMiddleware, async (req, res) => {
  try {
    const membership = await db.query(
      'SELECT role FROM organization_members WHERE organization_id = $1 AND user_id = $2',
      [req.params.id, req.userId]
    );
    if (membership.rows.length === 0) {
      return res.status(403).json({ error: 'You are not a member of this organization' });
    }
    if (membership.rows[0].role !== 'owner') {
      return res.status(403).json({ error: 'Only the owner can remove members' });
    }
    if (parseInt(req.params.userId) === req.userId) {
      return res.status(400).json({ error: 'Owner cannot remove themselves' });
    }

    const result = await db.query(
      'DELETE FROM organization_members WHERE organization_id = $1 AND user_id = $2 RETURNING user_id',
      [req.params.id, req.params.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Member not found in this organization' });
    }

    res.json({ message: 'Member removed' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/organizations/:id/expenses/:expenseId', authMiddleware, async (req, res) => {
  try {
    const membership = await db.query(
      'SELECT * FROM organization_members WHERE organization_id = $1 AND user_id = $2',
      [req.params.id, req.userId]
    );
    if (membership.rows.length === 0) {
      return res.status(403).json({ error: 'You are not a member of this organization' });
    }

    await db.query('DELETE FROM expense_splits WHERE expense_id = $1', [req.params.expenseId]);
    const result = await db.query(
      'DELETE FROM expenses WHERE id = $1 AND organization_id = $2 RETURNING id',
      [req.params.expenseId, req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Expense not found' });
    }

    res.json({ message: 'Expense deleted' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});
app.listen(PORT, () => {
  console.log(`Expense tracker server running on port ${PORT}`);
});
