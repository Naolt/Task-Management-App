const express = require("express");
const router = express.Router();
const fileController = require("../controllers/fileController");
const authMiddleware = require("../middlewares/authMiddleware");
const roleMiddleware = require("../middlewares/roleMiddleware");

// Export Data
router.get(
  "/",
  //authMiddleware,
  //roleMiddleware("admin"),
  fileController.exportData
);

module.exports = router;
