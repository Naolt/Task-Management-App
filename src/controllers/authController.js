//const { PrismaClient } = require("@prisma/client");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();
const { generateToken } = require("../utils/authUtils");
const { prisma } = require("../utils/prisma");
const speakeasy = require("speakeasy");
const QRCode = require("qrcode");
const logger = require("../utils/loggerUtil");
//const prisma = new PrismaClient();

//Temp: Get list of users
async function getUsers(req, res) {
  try {
    const users = await prisma.user.findMany();
    res.status(200).json(users);
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
}

async function registerUser(req, res) {
  const { username, email, password, role = "user" } = req.body;

  // Hash the password
  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    // Create a new user in the database
    const user = await prisma.user.create({
      data: {
        username,
        email,
        password: hashedPassword,
        role,
      },
    });

    // Respond with the created user
    logger.info("User registered successfully", {
      action: "registerUser",
      timestamp: new Date().toISOString(),
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
      },
      hostname: req.hostname, // Assuming you want to log the hostname
    });
    res.status(201).json(user);
  } catch (error) {
    logger.error("Error registering user", {
      action: "registerUser",
      timestamp: new Date().toISOString(),
      error: error.message,
      hostname: req.hostname, // Assuming you want to log the hostname
    });
    console.error("Error registering user:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
}

async function loginUser(req, res) {
  const { email, password } = req.body;
  console.log(email, password);

  try {
    // Find the user by email
    const user = await prisma.user.findUnique({
      where: { email },
    });

    // Verify the password
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!user || !passwordMatch) {
      logger.warn("Invalid credentials", {
        action: "loginUser",
        timestamp: new Date().toISOString(),
        email,
        hostname: req.hostname, // Assuming you want to log the hostname
      });
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Generate JWT token
    const secret = speakeasy.generateSecret();
    const secretBase32 = secret.base32;

    // Store the secret key in the user's record
    await prisma.user.update({
      where: { id: user.id },
      data: { twoFactorSecret: secretBase32 },
    });

    // Get the data URL of the authenticator URL
    QRCode.toDataURL(secret.otpauth_url, function (err, data_url) {
      //console.log(data_url);
      logger.info("User logged in successfully", {
        action: "loginUser",
        timestamp: new Date().toISOString(),
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          role: user.role,
        },
        hostname: req.hostname, // Assuming you want to log the hostname
      });
      res.json({ totpUri: data_url, ...user });
    });
  } catch (error) {
    logger.error("Error logging in user", {
      action: "loginUser",
      timestamp: new Date().toISOString(),
      error: error.message,
      email,
      hostname: req.hostname, // Assuming you want to log the hostname
    });
    console.error("Error logging in user:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
}

async function verifyTwoFactorAuth(req, res) {
  const { code, id } = req.body;
  console.log(req.body);
  const userId = id;

  try {
    // Find the user by id
    const user = await prisma.user.findUnique({
      where: { id: userId },
    });
    console.log("here is the user", user);
    // Verify the TOTP token
    const isValidToken = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: "base32",
      token: code,
      window: 10000, // Allow codes that are generated within a time window (e.g., 2 seconds)
    });

    if (isValidToken) {
      // Generate JWT token
      const token = generateToken(
        user.id,
        user.username,
        user.email,
        user.role
      );

      // Respond with the generated token
      let response = { token, ...user };
      delete response["password"];
      res.json(response);
    } else {
      res
        .status(401)
        .json({ error: "Invalid two-factor authentication token" });
    }
  } catch (error) {
    console.error("Error verifying two-factor authentication:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
}

async function validateRecaptcha(req, res) {
  const { recaptchaToken } = req.body;

  const secretKey = process.env.RECAPTCHA_SECRET_KEY;
  const verificationURL = `https://www.google.com/recaptcha/api/siteverify`;

  try {
    const response = await fetch(verificationURL, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: `secret=${secretKey}&response=${recaptchaToken}`,
    });

    const data = await response.json();

    if (data.success) {
      logger.info("reCAPTCHA verification successful", {
        action: "validateRecaptcha",
        timestamp: new Date().toISOString(),
        challenge: recaptchaToken, // Assuming you want to log the recaptcha token
        hostname: req.hostname, // Assuming you want to log the hostname
      });
      return res.json({ success: true });
    } else {
      logger.warn("Invalid reCAPTCHA token", {
        action: "validateRecaptcha",
        timestamp: new Date().toISOString(),
        challenge: recaptchaToken, // Assuming you want to log the recaptcha token
        hostname: req.hostname, // Assuming you want to log the hostname
      });
      return res.status(400).json({ error: "Invalid reCAPTCHA token" });
    }
  } catch (error) {
    logger.error("Error validating reCAPTCHA token", {
      action: "validateRecaptcha",
      timestamp: new Date().toISOString(),
      error: error.message,
      challenge: recaptchaToken, // Assuming you want to log the recaptcha token
      hostname: req.hostname, // Assuming you want to log the hostname
    });
    console.error("Error validating reCAPTCHA token:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
}

// Validate user registration data
const validateUserRegistration = (req, res, next) => {
  const { username, email, password } = req.body;

  // Check if required fields are present
  if (!username || !email || !password) {
    return res.status(400).json({ error: "All fields are required" });
  }

  // Validate username and email uniqueness
  prisma.user
    .findMany({
      where: {
        OR: [{ username }, { email }],
      },
    })
    .then((existingUsers) => {
      const duplicateUsername = existingUsers.some(
        (user) => user.username === username
      );
      const duplicateEmail = existingUsers.some((user) => user.email === email);

      if (duplicateUsername) {
        return res.status(400).json({ error: "Username is already taken" });
      }

      if (duplicateEmail) {
        return res.status(400).json({ error: "Email is already taken" });
      }

      next();
    })
    .catch((error) => {
      console.error("Error validating user registration:", error);
      res.status(500).json({ error: "Internal Server Error" });
    });
};

module.exports = {
  registerUser,
  loginUser,
  validateUserRegistration,
  getUsers,
  verifyTwoFactorAuth,
  validateRecaptcha,
};
