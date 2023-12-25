const asyncHandler = require("express-async-handler");
const User = require("../models/userModel");
const jwt = require("jsonwebtoken");

const protect = asyncHandler(async (req, res, next) => {
    try {
        const token = req.cookies.token
        if (!token) {
            res.status(401)
            throw new Error("Not authorized ,please login")
        }

        //verify token
        const verified = jwt.verify(token, process.env.JWT_SECRET);
        // get user id from token
        const user = await User.findById(verified.id).select("-password")
        if (!user) {
            res.status(401)
            throw new Error("User not found");
        }
        // Set the SameSite attribute to None for cross-site usage
        res.cookie("token", token, {
            httpOnly: true,
            secure: true, // Make sure to set this for HTTPS
            sameSite: "None",
            expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // Adjust the expiration as needed
        });
        req.user = user;
        next()
    } catch (error) {
        res.status(401)
        throw new Error("Not authorized ,please login");
    }
});

module.exports = protect