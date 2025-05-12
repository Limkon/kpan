require('dotenv').config();

module.exports = {
  secret: process.env.JWT_SECRET || "default_fallback_secret_key_if_not_in_env",
  jwtExpiration: 3600,           // 1 hour
  jwtRefreshExpiration: 86400,   // 24 hours
};
