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

const app = express();


// Middlewares
app.use(
  cors({
    origin: ["http://localhost:3000","https://merchant-frontend.onrender.com"],
    credentials: true,
    methods:["CONNECT"," DELETE", "GET","HEAD", "OPTIONS", "PATCH", "POST", "PUT"],
    allowedHeaders: ["Content-Type", "Authorization"],

  })
);
app.use(express.json());
app.use(cookieParser());
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