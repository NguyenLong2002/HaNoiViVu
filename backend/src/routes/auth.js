const router = require("express").Router();
const authController = require("../controllers/authController");
const middlewareController = require("../controllers/middlewareController");

// Register user
router.post("/register", authController.registerUser);

// Verify email
router.get("/verify-email", authController.verifyEmail);

// Login user
router.post("/login", authController.loginUser);

// Refresh token
router.post("/refresh", authController.requestRefreshToken);

// Logout user
router.post("/logout", middlewareController.verifyToken, authController.logoutUser);

// Request password reset
router.post("/request-reset",authController.requestPasswordReset);

//Reset password
router.post("/reset-password/:token", authController.resetPassword);
module.exports = router;
