import { Router } from "express";
import {
  listUsers,
  getUser,
  deleteUser,
} from "../controllers/user.controller.js";
import { authenticate } from "../middlewares/auth.middleware.js";
import { requireRole } from "../middlewares/role.middleware.js";

/**
 * TODO: Define user routes (all require admin role)
 *
 * GET    /           → listUsers (requires authenticate and requireRole('admin'))
 * GET    /:id        → getUser (requires authenticate and requireRole('admin'))
 * DELETE /:id        → deleteUser (requires authenticate and requireRole('admin'))
 *
 * Apply authenticate middleware to all routes
 * Apply requireRole('admin') middleware to all routes
 */

const router = Router();

// Your routes here
router.route("/").get(authenticate, requireRole("admin"), listUsers);
router
  .route("/:id")
  .get(authenticate, requireRole("admin"), getUser)
  .delete(authenticate, requireRole("admin"), deleteUser);

export default router;
