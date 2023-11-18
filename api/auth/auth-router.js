const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const Users = require('../users/users-model')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')

router.post("/register", validateRoleName, (req, res, next) => {

    const {username, password} = req.body
    const {role_name} = req
    const hash = bcrypt.hashSync(password, 8)

    Users.add({username, password: hash, role_name})
      .then (something => {
        res.status(201).json(something)
      })
      .catch (next)
});

function buildToken (user) {
  const payload = {
    subject: user.user_id,
    role_name: user.role_name,
    username: user.username
  }
  const options = {
    expiresIn: '1d',
  }
  return jwt.sign(payload, JWT_SECRET, options)
}

router.post("/login", checkUsernameExists, async (req, res, next) => {
  try {
    if (bcrypt.compareSync(req.body.password, req.user.password)) {
      const token = buildToken(req.user)
      res.status(200).json({
        message: `${req.user.username} is back!`,
        token
      })
    }
    else {
      res.status(401).json({message: 'Invalid credentials'})
    }
  }
  catch (error) {
    next(error)
  }




  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
});

module.exports = router;
