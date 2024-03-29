const dotenv = require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const cors = require("cors");
const userRoute = require("./routes/userRoute");
const productRoute = require("./routes/productRoute");
const contactRoute = require("./routes/contactRoute");
const errorHandler =require("./middleWare/errorMiddleware");
const cookieParser = require("cookie-parser");
const path = require("path");
const helmet= require("helmet");

const app = express();


// Middlewares
app.use(cors({
  origin: (origin, callback) => {
    const allowedOrigins = ["http://localhost:3000", "https://merchant-frontend-eosin.vercel.app"];
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
  credentials: true,
  methods:["CONNECT"," DELETE", "GET","HEAD", "OPTIONS", "PATCH", "POST", "PUT"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));

app.use(helmet());
app.use(express.json());
app.use(cookieParser());


app.use((_, res, next) => {
  res.setHeader('Set-Cookie', 'HttpOnly;Secure;SameSite=None');
  next();
});

app.use(express.urlencoded({ extended: false }));
app.use(bodyParser.json());


app.use("/uploads", express.static(path.join(__dirname, "uploads")));




// Routes Middleware
app.use("/api/users", userRoute);
app.use("/api/products", productRoute);
app.use("/api/contactus", contactRoute);



  

// Routes
app.get("/", (req, res) => {
  res.header('Access-Control-Allow-Origin', '*');
    res.send("Home Page");
  });

  //error middleware
app.use(errorHandler);

// Connect to DB and start server
const PORT = process.env.PORT || 5000;
mongoose
  .set('strictQuery', true)
  .connect(process.env.MONGO_URI)
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Server Running on port ${PORT}`);
    });
  })
  .catch((err) => console.log(err));