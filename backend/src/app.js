const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const mongoose = require("mongoose");
const cookieParser = require("cookie-parser");

const authRouter = require('./routes/auth');
const userRouter = require('./routes/user');

dotenv.config(); // Load biến môi trường từ tệp .env

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(cors());

// Connect to database

mongoose.connect(process.env.MONGO_URL)
   .then(() => {
      console.log("Kết nối thành công!");
   })
   .catch((error) => {
      console.error("Kết nối thất bại:", error);
   });

// Routes
app.use("/v1/auth", authRouter);
app.use("/v1/user", userRouter);

app.listen(8000, () => {
  console.log(`Server running on port 8000`);
});
