const express = require("express");
const router = express.Router();
const projectController = require("../controllers/projectController");
const taskController = require("../controllers/taskController");
const authMiddleware = require("../middlewares/authMiddleware");
const roleMiddleware = require("../middlewares/roleMiddleware");

// Fetch all projects route
router.get("/", authMiddleware, projectController.getAllProjects);

// Fetch all user projects route
router.get(
  "/getUserProjects",
  authMiddleware,
  projectController.getUserProjects
);

// Create a new project route
router.post(
  "/",
  authMiddleware,
  projectController.validateProjectCreation,
  projectController.createProject
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

// Add members from a project route
router.post(
  "/:projectId/members",
  authMiddleware,
  roleMiddleware("admin"),
  projectController.addMemberToProject
);

// remove members from a project route
router.delete(
  "/:projectId/members/:userId",
  authMiddleware,
  roleMiddleware("admin"),
  projectController.removeMemberFromProject
);
module.exports = router;
