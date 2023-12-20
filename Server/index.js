const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const { Client, Pool } = require("pg");

const app = express();
const port = 3000;
app.use(bodyParser.json());

const dotenv = require("dotenv");
dotenv.config({ path: "./.env" });

const pool = new Pool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  database: process.env.DB_DATABASE,
  port: process.env.DB_PORT,
  password: process.env.DB_PASSWORD,
});

// Registration
app.post("/register", async (req, res) => {
  const { firstname, lastname, username, password, confirmpassword } = req.body;

  // Check if passwords match
  if (password !== confirmpassword) {
    return res.status(400).json({ error: "Passwords do not match" });
  }

  // Hash the password
  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    // Insert user into the database
    const result = await pool.query(
      "INSERT INTO users (firstname, lastname, username, password) VALUES ($1, $2, $3, $4) RETURNING id",
      [firstname, lastname, username, hashedPassword]
    );

    res.json({ id: result.rows[0].id });
  } catch (error) {
    console.error("Error during registration:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

//Login
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  //retrieve user from database
  const result = await pool.query("SELECT * FROM users WHERE username = $1", [
    username,
  ]);
  const user = result.rows[0];

  //if user not found
  if (!user) {
    return res.status(401).json({ error: "Invalid username or password" });
  }

  // Compare hashed password
  const passwordMatch = await bcrypt.compare(password, user.password);

  if (!passwordMatch) {
    return res.status(401).json({ error: "Invalid username or password" });
  }

  res.json({ message: "Login successful" });
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
