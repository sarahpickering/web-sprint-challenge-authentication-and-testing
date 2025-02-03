const { JWT_SECRET } = require('../secrets/secrets');
const jwt = require('jsonwebtoken');
const User = require('../users/users-model');

const restriction = (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) {
    return res.status(401).json({ message: 'token required' })
  }
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: "token invalid" });
    }
    req.decodedJwt = decoded;
    next();
  });
};

const checkUsernameExists = async (req, res, next) => {
  try {
    const { username } = req.body;
    if (!username) {
      return res.status(401).json({ message: "invalid credentials" });
    }

    const user = await User.findBy({ username }).first();
    if (!user) {
      return res.status(401).json({ message: "invalid credentials" });
    }
    next();
  } catch (error) {
    next(error);
  }
};

function buildToken(user) {
  const payload = {
    subject: user.user_id,
    username: user.username,
  };
  const options = {
    expiresIn: "1d",
  };
  return jwt.sign(payload, JWT_SECRET, options);
}

(module.exports = restriction), checkUsernameExists, buildToken;