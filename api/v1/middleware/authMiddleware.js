const jwt = require('jsonwebtoken');
const { auth } = require('express-oauth2-jwt-bearer');
const { UserInfoClient } = require('auth0');
const User = require('../models/users');
const connectDB = require('../config/db'); // Import your connection helper
const { ensureStripeCustomer } = require('../controllers/authController'); 

const checkAuth0Jwt = auth({
  audience: process.env.AUTH0_AUDIENCE,
  issuerBaseURL: `https://${process.env.AUTH0_DOMAIN}/`,
});

const userInfoClient = new UserInfoClient({ domain: process.env.AUTH0_DOMAIN });

exports.protect = async (req, res, next) => {
  // CRITICAL: Ensure database connection is ready before any logic
  await connectDB(); 

  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ success: false, error: 'No token' });
    }

    const token = authHeader.split(' ')[1];
    const isAuth0Token = token.length > 250;

    if (isAuth0Token) {
      // --- AUTH0 FLOW ---
      return checkAuth0Jwt(req, res, async (err) => {
        if (err) {
          console.error("Auth0 JWT Validation Failed:", err.message);
          return res.status(401).json({ success: false, error: 'Invalid Auth0 Token' });
        }
        
        try {
          const accessToken = req.auth.token;
          let email = req.auth.payload['https://api.marketplace.com/email'] 
                      || req.auth.payload.email 
                      || (await userInfoClient.getUserInfo(accessToken)).email;
          
          if (!email) throw new Error("No email found in token");

          const normalizedEmail = email.toLowerCase().trim();
          let user = await User.findOne({ email: normalizedEmail });
          
          if (!user) {
             console.log(`JIT Provisioning: ${normalizedEmail}`);
             user = await User.create({ 
               email: normalizedEmail, 
               name: req.auth.payload.name || 'Auth0 User', 
               passwordHash: 'AUTH0_MANAGED' 
             });
             await ensureStripeCustomer(user);
          }

          req.user = { id: user._id.toString() }; 
          next();
        } catch (e) {
          console.error("Auth0 JIT Error:", e.message);
          res.status(500).json({ success: false, error: 'Auth0 processing failed' });
        }
      });
    } else {
      // --- LOCAL JWT FLOW ---
      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.id);
        if (!user) return res.status(401).json({ success: false, error: 'User does not exist' });
        
        req.user = { id: user._id.toString() };
        next();
      } catch (err) {
        console.error("Local JWT Error:", err.message);
        return res.status(401).json({ success: false, error: 'Invalid local token' });
      }
    }
  } catch (err) {
    console.error("Global Middleware Catch:", err.message);
    res.status(500).json({ success: false, error: 'Authentication service failure' });
  }
};