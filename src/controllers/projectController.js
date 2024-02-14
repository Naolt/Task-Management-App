//const { PrismaClient } = require("@prisma/client");
//const prisma = new PrismaClient();
const { prisma } = require("../utils/prisma");

// Get list of Projects of the current user
async function getAllProjects(req, res) {
  try {
    const { search, user_id } = req.query;

    // Define the base filter based on the user's role and user_id (if provided)
    const baseFilter = {
      ...(req.user.role === "admin" && user_id
        ? { user_id: parseInt(user_id, 10) }
        : { user_id: req.user.id }),
    };

    // Add search condition if a search term is provided
    const searchFilter = search
      ? {
          OR: [
            { name: { contains: search, mode: "insensitive" } },
            { description: { contains: search, mode: "insensitive" } },
          ],
        }
      : {};

    const projects = await prisma.project.findMany({
      where: {
        ...baseFilter,
        ...searchFilter,
      },
      include: {
        projectMembers: true,
      },
    });

    res.json(projects);
  } catch (error) {
    console.error("Error fetching projects:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
}

// Get User Projects
async function getUserProjects(req, res) {
  const user = req.user; // Assuming user information is stored in req.user after authentication

  try {
    // Fetch the projects owned by the user
    const ownedProjects = await prisma.project.findMany({
      where: {
        user: {
          id: user.id,
        },
      },
    });

    // Fetch the projects where the user is a member
    const memberProjects = await prisma.projectMembers.findMany({
      where: {
        user: {
          id: user.id,
        },
      },
      include: {
        project: true,
      },
    });

    // Construct the response object
    const response = {
      ownedProjects,
      memberProjects: memberProjects.map((member) => member.project),
    };

    // Respond with the project information
    res.json(response);
  } catch (error) {
    console.error("Error fetching project information:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
}

// Create a new project
async function createProject(req, res) {
  const { name, description } = req.body;

  try {
    // Check if user is an admin and a user_id is provided in the query parameters
    if (req.user.role === "admin" && req.query.user_id) {
      const project = await prisma.project.create({
        data: {
          name,
          description,
          user: { connect: { id: parseInt(req.query.user_id, 10) } },
        },
      });

      res.status(201).json(project);
    } else {
      // Create a new project for the authenticated user
      const project = await prisma.project.create({
        data: {
          name,
          description,
          user: { connect: { id: req.user.id } },
        },
      });

      res.status(201).json(project);
    }
  } catch (error) {
    console.error("Error creating project:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
}

// Fetches the project by its id
async function getProjectById(req, res) {
  const projectId = parseInt(req.params.projectId, 10);

  try {
    // Check if user is an admin and a user_id is provided in the query parameters
    if (req.user.role === "admin" && req.query.user_id) {
      const project = await prisma.project.findUnique({
        where: { id: projectId, user_id: parseInt(req.query.user_id, 10) },
      });
      if (!project) {
        return res.status(404).json({ error: "Project not found" });
      }
      res.json(project);
    } else {
      // Get a specific project by ID for the authenticated user
      const project = await prisma.project.findUnique({
        where: { id: projectId, user_id: req.user.id },
      });
      if (!project) {
        return res.status(404).json({ error: "Project not found" });
      }
      res.json(project);
    }
  } catch (error) {
    console.error("Error fetching project by ID:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
}

// Update project by its id
async function updateProjectById(req, res) {
  const projectId = parseInt(req.params.projectId, 10);
  const { name, description } = req.body;

  try {
    // Check if user is an admin and a user_id is provided in the query parameters
    if (req.user.role === "admin" && req.query.user_id) {
      const updatedProject = await prisma.project.update({
        where: { id: projectId, user_id: parseInt(req.query.user_id, 10) },
        data: { name, description },
      });

      res.json(updatedProject);
    } else {
      // Update a specific project by ID for the authenticated user
      const updatedProject = await prisma.project.update({
        where: { id: projectId, user_id: req.user.id },
        data: { name, description },
      });

      res.json(updatedProject);
    }
  } catch (error) {
    console.error("Error updating project by ID:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
}

// Delete project by its id
async function deleteProjectById(req, res) {
  const projectId = parseInt(req.params.projectId, 10);

  try {
    // Check if user is an admin and a user_id is provided in the query parameters
    if (req.user.role === "admin" && req.query.user_id) {
      // Delete a specific project by ID for the specified user
      await prisma.project.delete({
        where: { id: projectId, user_id: parseInt(req.query.user_id, 10) },
      });
    } else {
      // Delete a specific project by ID for the authenticated user
      await prisma.project.delete({
        where: { id: projectId, user_id: req.user.id },
      });
    }

    res.status(204).json({ message: "Project deleted successfully" });
  } catch (error) {
    console.error("Error deleting project by ID:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
}

// Add a member to a project
async function addMemberToProject(req, res) {
  const { projectId } = req.params;
  const { userId } = req.body;

  try {
    // Check if the user is already a member of the project
    const existingMember = await prisma.projectMembers.findFirst({
      where: {
        project_id: Number(projectId),
        user_id: Number(userId),
      },
    });

    if (existingMember) {
      return res
        .status(400)
        .json({ error: "User is already a member of the project" });
    }

    // Add the user as a member of the project
    await prisma.projectMembers.create({
      data: {
        project_id: Number(projectId),
        user_id: Number(userId),
      },
    });

    res.status(201).json({ message: "User added to the project successfully" });
  } catch (error) {
    console.error("Error adding member to project:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
}

// Remove a member from a project
async function removeMemberFromProject(req, res) {
  const { projectId, userId } = req.params;

  try {
    // Remove the user from the project
    await prisma.projectMembers.deleteMany({
      where: {
        project_id: Number(projectId),
        user_id: Number(userId),
      },
    });

    res
      .status(200)
      .json({ message: "User removed from the project successfully" });
  } catch (error) {
    console.error("Error removing member from project:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
}

// Validate project creation data
function validateProjectCreation(req, res, next) {
  const { name } = req.body;

  // Check if required fields are present
  if (!name) {
    return res.status(400).json({ error: "Project name is required" });
  }

  next();
}

module.exports = {
  getAllProjects,
  createProject,
  getProjectById,
  updateProjectById,
  deleteProjectById,
  validateProjectCreation,
  addMemberToProject,
  removeMemberFromProject,
  getUserProjects,
};
