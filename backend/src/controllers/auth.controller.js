import bcrypt from "bcrypt";

import { db } from "../db/index.js";
import { usersTable } from "../db/schema/users.schema.js";
import { eq } from "drizzle-orm";
import { generateToken } from "../utils/token.js";

/*
|--------------------------------------------------------------------------
| Register
|--------------------------------------------------------------------------
*/

export const registerUser = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    /*
    |--------------------------------------------------------------------------
    | Validation
    |--------------------------------------------------------------------------
    */

    if (!name || !email || !password) {
      return res.status(400).json({
        success: false,
        message: "All fields are required",
      });
    }

    /*
    |--------------------------------------------------------------------------
    | Check Existing User
    |--------------------------------------------------------------------------
    */

    const existingUser = await db
      .select()
      .from(usersTable)
      .where(eq(usersTable.email, email));

    if (existingUser.length > 0) {
      return res.status(400).json({
        success: false,
        message: "User already exists",
      });
    }

    /*
    |--------------------------------------------------------------------------
    | Hash Password
    |--------------------------------------------------------------------------
    */

    const hashedPassword = await bcrypt.hash(
      password,
      10
    );

    /*
    |--------------------------------------------------------------------------
    | Create User
    |--------------------------------------------------------------------------
    */

    const newUser = await db
      .insert(usersTable)
      .values({
        name,
        email,
        password: hashedPassword,
      })
      .returning();

    /*
    |--------------------------------------------------------------------------
    | Generate Token
    |--------------------------------------------------------------------------
    */

    const token = generateToken(newUser[0]);

    return res.status(201).json({
      success: true,
      message: "User registered successfully",

      token,

      user: {
        id: newUser[0].id,
        name: newUser[0].name,
        email: newUser[0].email,
      },
    });
  } catch (error) {
    console.error(error);

    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

/*
|--------------------------------------------------------------------------
| Login
|--------------------------------------------------------------------------
*/

export const loginUser = async (req, res) => {
  try {
    const { email, password } = req.body;

    /*
    |--------------------------------------------------------------------------
    | Validation
    |--------------------------------------------------------------------------
    */

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Email and password required",
      });
    }

    /*
    |--------------------------------------------------------------------------
    | Find User
    |--------------------------------------------------------------------------
    */

    const user = await db
      .select()
      .from(usersTable)
      .where(eq(usersTable.email, email));

    if (user.length === 0) {
      return res.status(400).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    /*
    |--------------------------------------------------------------------------
    | Compare Password
    |--------------------------------------------------------------------------
    */

    const isPasswordCorrect =
      await bcrypt.compare(
        password,
        user[0].password
      );

    if (!isPasswordCorrect) {
      return res.status(400).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    /*
    |--------------------------------------------------------------------------
    | Generate Token
    |--------------------------------------------------------------------------
    */

    const token = generateToken(user[0]);

    return res.status(200).json({
      success: true,
      message: "Login successful",

      token,

      user: {
        id: user[0].id,
        name: user[0].name,
        email: user[0].email,
      },
    });
  } catch (error) {
    console.error(error);

    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

export const logoutUser = async (req, res) => {
  try {
    // Since we're using JWTs, logout can be handled on the client side by simply deleting the token.
    // Optionally, you can implement token blacklisting on the server side for added security.
    return res.status(200).json({
      success: true,
      message: "Logout successful",
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

/*
|--------------------------------------------------------------------------
| Current User
|--------------------------------------------------------------------------
*/

export const getCurrentUser = async (
  req,
  res
) => {
  try {
    const user = await db
      .select({
        id: usersTable.id,
        name: usersTable.name,
        email: usersTable.email,
        createdAt: usersTable.createdAt,
      })
      .from(usersTable)
      .where(eq(usersTable.id, req.user.id));

    return res.status(200).json({
      success: true,
      user: user[0],
    });
  } catch (error) {
    console.error(error);

    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};