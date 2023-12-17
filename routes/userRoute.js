const express = require("express");
const router = express.Router();
const { registerUser, loginUser, logout, getUser, loginStatus, updateUser, changePassword, forgotPassword, resetPassword }=require("../controllers/userController");
const protect = require("../middleWare/authMiddleware");


router.post("/register", registerUser);
router.post("/login", loginUser);
router.get("/logout", logout);
router.get("/getuser", protect,getUser);
router.get("/loggedin", loginStatus);
router.post("/updateuser", protect, updateUser);
router.post("/changepassword", protect, changePassword);
router.post("/forgotpassword",  forgotPassword);
router.put("/resetpassword/:resetToken",  resetPassword);


module.exports = router;