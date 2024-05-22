const User = require("../models/User");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { sendMail } = require("../utils/sendEmail");
require('dotenv').config(); // Load biến môi trường từ tệp .env

let refreshTokens = [];
const authController = {
    // REGISTER
    registerUser: async (req, res) => {
        try {
            const existingEmail = await User.findOne({ email: req.body.email });
            if (existingEmail) {
                return res.status(400).json({ message: 'Email already exists' });
            }

            const existingUsername = await User.findOne({ username: req.body.username });
            if (existingUsername) {
                return res.status(400).json({ message: 'Username already exists' });
            }

            const salt = await bcrypt.genSalt(10);
            const hashPass = await bcrypt.hash(req.body.password, salt);

            const newUser = new User({
                email: req.body.email,
                username: req.body.username,
                password: hashPass,
                emailVerified: false
            });

            await newUser.save();

            const token = jwt.sign(
                { id: newUser._id },
                process.env.EMAIL_VERIFICATION_SECRET,
                { expiresIn: '1d' }
            );

            const verificationLink = `${process.env.APP_URL}/v1/auth/verify-email?token=${token}`;
            const emailContent = `<p>Click <a href="${verificationLink}">here</a> to verify your email.</p>`;

            await sendMail(newUser.email, 'Email Verification', emailContent);

            res.status(200).json({ message: 'Registration successful, please check your email to verify your account' });
        } catch (error) {
            console.error('Registration error:', error);
            res.status(500).json({ message: 'Internal server error' });
        }
    },

    // Verify Email
    verifyEmail: async (req, res) => {
        try {
            const token = req.query.token;
    
            if (!token) {
                return res.status(400).json({ message: 'Missing token' });
            }
    
            const decodedToken = jwt.verify(token, process.env.EMAIL_VERIFICATION_SECRET);
            const userId = decodedToken.id;
    
            const user = await User.findById(userId);
    
            if (!user) {
                return res.status(404).json({ message: 'User not found' });
            }
    
            user.emailVerified = true;
            await user.save();
    
            // Chuyển hướng người dùng đến trang chủ sau khi xác thực thành công
            res.redirect(`${process.env.FRONTEND_URL}`);

        } catch (error) {
            console.error('Email verification error:', error);
            res.status(500).json({ message: 'Internal server error' });
        }
    },
    

    // GENERATE ACCESS TOKEN
    generateAccessToken: (user) => {
        return jwt.sign(
            {
                id: user._id,
                admin: user.admin,
            },
            process.env.ACCESS_TOKEN_SECRET,
            { expiresIn: "20s" }
        );
    },

    // GENERATE REFRESH TOKEN
    generateRefreshToken: (user) => {
        return jwt.sign(
            {
                id: user._id,
                admin: user.admin,
            },
            process.env.REFRESH_TOKEN_SECRET,
            { expiresIn: "365d" }
        );
    },

    // LOGIN
    loginUser: async (req, res) => {
        try {
            const user = await User.findOne({ username: req.body.username });
            if (!user) {
                return res.status(404).json({ success: false, message: 'Invalid username!' });
            }
            const validPassword = await bcrypt.compare(req.body.password, user.password);
            if (!validPassword) {
                return res.status(404).json({ success: false, message: 'Invalid password!' });
            }
            if (!user.emailVerified) {
                return res.status(403).json({ success: false, message: 'Email has not been verified!' });
            }
            const accessToken = authController.generateAccessToken(user);
            const refreshToken = authController.generateRefreshToken(user);
            refreshTokens.push(refreshToken);
            res.cookie("refreshToken", refreshToken, {
                httpOnly: true,
                secure: false,
                path: "/",
                sameSite: "strict",
            });
            const { password, ...others } = user._doc;
            res.status(200).json({ success: true, user: { ...others, accessToken } });
        } catch (err) {
            res.status(500).json({ success: false, message: 'Internal server error' });
        }
    },

    requestRefreshToken: async (req, res) => {
        const refreshToken = req.cookies.refreshToken;
        if (!refreshToken) return res.status(401).json("You're not authenticated");
        if (!refreshTokens.includes(refreshToken)) {
            return res.status(403).json("Refresh token is not valid");
        }
        jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
            if (err) {
                console.log(err);
            }
            refreshTokens = refreshTokens.filter((token) => token !== refreshToken);
            const newAccessToken = authController.generateAccessToken(user);
            const newRefreshToken = authController.generateRefreshToken(user);
            refreshTokens.push(newRefreshToken);
            res.cookie("refreshToken", newRefreshToken, {
                httpOnly: true,
                secure: false,
                path: "/",
                sameSite: "strict",
            });
            res.status(200).json({ accessToken: newAccessToken });
        });
    },

    // LOG OUT
    logoutUser: async (req, res) => {
        res.clearCookie("refreshToken");
        refreshTokens = refreshTokens.filter((token) => token !== req.cookies.refreshToken);
        res.status(200).json("Logged out!");
    }
};

module.exports = authController;
