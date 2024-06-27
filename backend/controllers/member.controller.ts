import asyncHandler from "express-async-handler";
import { Request, Response } from "express";
import bcrypt from "bcryptjs";
import { db } from "../config/database";

import { generateToken } from "../utils/generateToken";

export const signUp = asyncHandler(async (req: Request, res: Response) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const member = await db.member.create({
      data: {
        first_name: req.body.first_name,
        last_name: req.body.last_name,
        email: req.body.email,
        password: hashedPassword,
      },
    });

    const { accessToken, refreshToken } = await generateToken({
      id: member.id,
      email: req.body.email,
    });

    res.status(201).json({
      accessToken,
      refreshToken,
      message: "Account created successfully",
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({
      message: "Something went wrong",
    });
  }
});

export const signIn = asyncHandler(async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;
    const existingUser = await db.member.findUnique({
      where: {
        email: email,
      },
    });

    if (!existingUser) {
      res.status(404).json({
        message: "Invalid credentials",
      });
      return;
    }

    const isPasswordCorrect = await bcrypt.compare(
      password,
      existingUser.password
    );

    if (!isPasswordCorrect) {
      res.status(400).json({
        message: "Invalid credentials",
      });
      return;
    }

    const { accessToken, refreshToken } = await generateToken(existingUser);

    res.status(200).json({
      accessToken,
      refreshToken,
      accessTokenUpdatedAt: new Date().toLocaleString(),
      user: {
        id: existingUser.id,
        first_name: existingUser.first_name,
        last_name: existingUser.last_name,
        email: existingUser.email,
      },
    });
  } catch (error) {
    res.status(500).json({
      message: "Something went wrong",
    });
  }
});
