const express = require("express");
const router = express.Router();
const taskController = require("../controllers/taskController");
const authMiddleware = require("../middlewares/authMiddleware");
const roleMiddleware = require("../middlewares/roleMiddleware");
const attachmentMiddleware = require("../middlewares/attachmentMiddleware");

// Fetch a specific task by ID route
router.get(
  "/:taskId",
  authMiddleware,
  roleMiddleware("admin"),
  taskController.getTaskById
);

// Update a specific task by ID route
router.put(
  "/:taskId",
  authMiddleware,
  roleMiddleware("admin"),
  taskController.updateTaskById
);

// Delete a specific task by ID route
router.delete(
  "/:taskId",
  authMiddleware,
  roleMiddleware("admin"),
  taskController.deleteTaskById
);

// Upload attachment to a specific task route
router.post(
  "/:taskId/attachments",
  authMiddleware,
  attachmentMiddleware,
  taskController.uploadAttachment
);

// Get a specific attachment for a specific task route
router.get(
  "/:taskId/attachments/:attachmentId",
  authMiddleware,
  taskController.getAttachmentById
);

// Delete a specific attachment for a specific task route
router.delete(
  "/:taskId/attachments/:attachmentId",
  authMiddleware,
  taskController.deleteAttachmentById
);

// Assign a task to a user
router.put(
  "/:taskId/assign",
  authMiddleware,
  roleMiddleware("admin"), // Assuming only admins can assign tasks
  taskController.assignTask
);

// Unassign a task from a user
router.put(
  "/:taskId/unassign",
  authMiddleware,
  roleMiddleware("admin"), // Assuming only admins can unassign tasks
  taskController.unassignTask
);

module.exports = router;
