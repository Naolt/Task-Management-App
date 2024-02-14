const express = require("express");
const bodyParser = require("body-parser");
const authRoutes = require("./routes/authRoutes");
const projectRoutes = require("./routes/projectRoutes");
const taskRoutes = require("./routes/taskRoutes");
const profileRoutes = require("./routes/profileRoutes");
const exportRoutes = require("./routes/exportRoutes");
const cors = require("cors");

const app = express();

app.use(cors());
// Middleware for parsing JSON requests
app.use(bodyParser.json());

// load html file to test the socket connection
app.use(express.static("public"));

// Authentication routes
app.use("/api/auth", authRoutes);

// Project routes
app.use("/api/projects", projectRoutes);

// Task routes
app.use("/api/tasks", taskRoutes);

// Profile routes
app.use("/api/profile", profileRoutes);

// Export Data
app.use("/api/export", exportRoutes);
// Export the Express app instance
module.exports = { app };
