import { Instructor } from '../models/Instructor.js';
import sanitize from 'express-mongo-sanitize';
import bcrypt from 'bcrypt';

// =============================================================================
//  INSTRUCTOR PORTAL CONTROLLER  —  ⚠️ INTENTIONALLY VULNERABLE (security lab)
// =============================================================================
//
// Unlike the review/auth controllers in this project, these handlers do NOT
// validate input with Joi and the app has NO express-mongo-sanitize. They pass
// `req.body` / `req.query` straight into Mongoose. Because Express parses JSON
// bodies and bracket-notation query strings into nested objects, an attacker
// can smuggle MongoDB query operators ($ne, $gt, $regex, $where, ...) into
// what the code treats as plain strings.
//
// This is the bug students must find and fix. Do not "clean this up".
// =============================================================================

function publicProfile(doc) {
  return {
    id: doc._id.toString(),
    name: doc.name,
    username: doc.username,
    department: doc.department,
    role: doc.role
  };
}

// POST /api/instructors/login
export async function loginInstructor(req, res, next) {
  try {
    sanitize.sanitize(req.body);

    const { username, password } = req.body;
    if (
      typeof username !== 'string' ||
      typeof password !== 'string' ||
      !username.trim() ||
      !password.trim()
    ) {
      return res.status(400).json({ message: 'username and password are required' });
    }

    const instructor = await Instructor.findOne({ username });

    if (!instructor) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    let isPasswordValid = false;
    if (instructor.password && instructor.password.startsWith('$2b$')) {
      isPasswordValid = await bcrypt.compare(password, instructor.password);
    } else {
      isPasswordValid = instructor.password === password;
    }

    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    return res.json({ instructor: publicProfile(instructor) });
  } catch (err) {
    next(err);
  }
}

// GET /api/instructors
// Public directory. Deliberately limited fields so the contrast with the
// leaky /search endpoint below is obvious.
export async function getDirectory(req, res, next) {
  try {
    const instructors = await Instructor.find()
      .select('name department role')
      .sort({ name: 1 })
      .lean();
    res.json({ instructors });
  } catch (err) {
    next(err);
  }
}

// GET /api/instructors/search
export async function searchInstructors(req, res, next) {
  try {
    sanitize.sanitize(req.query);

    const filter = {};

    // Ensure parameters are strictly primitive strings to completely block operator injection ($ne, $regex, etc.)
    if (req.query.name !== undefined) {
      if (typeof req.query.name === 'string') {
        filter.name = { $regex: req.query.name, $options: 'i' };
      } else {
        return res.status(400).json({ message: 'Invalid name parameter format' });
      }
    }

    if (req.query.department !== undefined) {
      if (typeof req.query.department === 'string') {
        filter.department = req.query.department;
      } else {
        return res.status(400).json({ message: 'Invalid department parameter format' });
      }
    }

    if (req.query.role !== undefined) {
      if (typeof req.query.role === 'string') {
        filter.role = req.query.role;
      } else {
        return res.status(400).json({ message: 'Invalid role parameter format' });
      }
    }

    const instructors = await Instructor.find(filter)
      .select('name username department role')
      .lean();
    res.json({ count: instructors.length, instructors });
  } catch (err) {
    next(err);
  }
}