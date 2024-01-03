const path = require("path");
const fs = require("fs");
//const { PrismaClient } = require("@prisma/client");
//const prisma = new PrismaClient();
const { prisma } = require("../utils/prisma");

// Upload attachment to a specific task route
const uploadAttachment = async (req, res) => {
  try {
    const { taskId } = req.params;
    console.log(req.files);

    // Check if files are present
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ error: "No files uploaded" });
    }

    // Process each file and create attachments
    const attachments = [];
    for (const file of req.files) {
      const { originalname, filename, path } = file;

      const attachment = await prisma.attachment.create({
        data: {
          originalname,
          filename,
          path,
          task: { connect: { id: Number(taskId) } },
        },
      });

      attachments.push(attachment);
    }

    res.status(201).json(attachments);
  } catch (error) {
    console.error("Error uploading attachment:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
};

// Get a specific attachment for a specific task route
const getAttachmentById = async (req, res) => {
  try {
    const { taskId, attachmentId } = req.params;

    const attachment = await prisma.attachment.findUnique({
      where: { id: Number(attachmentId), task_id: Number(taskId) },
    });

    if (!attachment) {
      return res.status(404).json({ error: "Attachment not found" });
    }

    const filePath = path.join(__dirname, "../../uploads", attachment.filename);

    // Send the file to the client
    res.sendFile(filePath);
  } catch (error) {
    console.error("Error fetching attachment:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
};

// Delete a specific attachment for a specific task route
const deleteAttachmentById = async (req, res) => {
  try {
    const { taskId, attachmentId } = req.params;

    const attachment = await prisma.attachment.findUnique({
      where: { id: Number(attachmentId), task_id: Number(taskId) },
    });

    if (!attachment) {
      return res.status(404).json({ error: "Attachment not found" });
    }

    // Remove the file from the uploads folder
    const filePath = path.join(__dirname, "../../uploads", attachment.filename);
    fs.unlinkSync(filePath);

    // Delete the attachment from the database
    await prisma.attachment.delete({
      where: { id: Number(attachmentId), task_id: Number(taskId) },
    });

    res.status(204).json({ message: "Attachment deleted successfully" });
  } catch (error) {
    console.error("Error deleting attachment:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
};

module.exports = {
  uploadAttachment,
  getAttachmentById,
  deleteAttachmentById,
};
