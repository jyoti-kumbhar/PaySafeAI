const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Connect to MongoDB Atlas with correct DB
mongoose.connect("mongodb+srv://kumbharjyotics232444:2rJuzrAMbUS9ZtQB@cluster0.rlkth.mongodb.net/PaySafeAI?retryWrites=true&w=majority", {
  dbName: "PaySafeAI"   
})
.then(() => {
  console.log(" MongoDB Connected");
  console.log(" Connected DB:", mongoose.connection.name);
})
.catch(err => console.error(" DB Connection Error:", err));


//  User Schema
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String
});

// collection name = "user"
const User = mongoose.models.User || mongoose.model("users", userSchema, "users");


// Signup Route
app.post("/signup", async (req, res) => {
  console.log(" Signup request received:", req.body);
  try {
    const { name, email, password } = req.body;

    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: "User already exists" });

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({ name, email, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ message: "User registered successfully" });
  } catch (err) {
    res.status(500).json({ message: "Error creating user", error: err.message });
  }
});

// Login Route
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Admin login check
    if (email === "admin@gmail.com" && password === "admin123") {
      return res.status(200).json({ message: "Admin login successful", role: "admin" });
    }

    // Check if user exists
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "Invalid email or password" });

    // Compare password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Invalid email or password" });

    res.status(200).json({ message: "User login successful", role: "user", user: { name: user.name, email: user.email } });
  } catch (err) {
    res.status(500).json({ message: "Error logging in", error: err.message });
  }
});

// Get all users (admin)
app.get("/admin/users", async (req, res) => {
  try {
    const users = await User.find({}, { password: 0 }); // exclude password
    res.json(users);
  } catch (err) {
    res.status(500).json({ message: "Error fetching users", error: err.message });
  }
});

// Delete a user (admin)
app.delete("/admin/users/:id", async (req, res) => {
  try {
    const { id } = req.params;
    await User.findByIdAndDelete(id);
    res.json({ message: "User deleted successfully" });
  } catch (err) {
    res.status(500).json({ message: "Error deleting user", error: err.message });
  }
});


//  Start server
app.listen(5000, () => {
  console.log("🚀 Server running on http://localhost:5000");
});
