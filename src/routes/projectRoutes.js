const express = require("express");
const router = express.Router();
const projectController = require("../controllers/projectController");
const taskController = require("../controllers/taskController");
const authMiddleware = require("../middlewares/authMiddleware");
const roleMiddleware = require("../middlewares/roleMiddleware");

// Fetch all projects route
router.get("/", authMiddleware, projectController.getAllProjects);

// Create a new project route
router.post(
  "/",
  authMiddleware,
  projectController.validateProjectCreation,
  projectController.createProject
);

// Fetch all tasks for a specific project route
router.get(
  "/:projectId/tasks",
  authMiddleware,
  roleMiddleware("admin"),
  taskController.getAllTasksForProject
);

// Create a new task within a project route
router.post(
  "/:projectId/tasks",
  authMiddleware,
  roleMiddleware("admin"),
  taskController.validateTaskCreation,
  taskController.createTask
);

// Fetch a specific project by ID route
router.get(
  "/:projectId",
  authMiddleware,
  roleMiddleware("admin"),
  projectController.getProjectById
);

// Update a specific project by ID route
router.put(
  "/:projectId",
  authMiddleware,
  roleMiddleware("admin"),
  projectController.updateProjectById
);

// Delete a specific project by ID route
router.delete(
  "/:projectId",
  authMiddleware,
  roleMiddleware("admin"),
  projectController.deleteProjectById
);

module.exports = router;
