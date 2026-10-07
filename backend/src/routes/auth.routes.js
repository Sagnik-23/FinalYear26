import express from "express";

import {
  registerUser,
  loginUser,
  getCurrentUser,
} from "../controllers/auth.controller.js";

import { verifyToken } from "../middleware/auth.middleware.js";

const authRouter = express.Router();

/*
|--------------------------------------------------------------------------
| Public Routes
|--------------------------------------------------------------------------
*/

authRouter.post("/register", registerUser);

authRouter.post("/login", loginUser);

/*
|--------------------------------------------------------------------------
| Protected Routes
|--------------------------------------------------------------------------
*/

authRouter.get("/me", verifyToken, getCurrentUser);

export default authRouter;