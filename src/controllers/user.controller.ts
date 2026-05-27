import type { Request, Response } from "express"
import { prisma } from '../db/db'
import { ApiResponse } from "../utils/ApiResponse"
import { ApiError } from "../utils/ApiError"
import { generateAccessToken, generateRefreshToken, passwordChecking, passwordHashing } from "../utils/auth"
import asyncHandler from '../utils/asyncHandler'


const generateAccessAndRefreshToken = async (userId: number): Promise<{ accessToken: string, refreshToken: string }> => {

  try {
    const user = await prisma.user.findUnique({
      where: {
        id: userId,
      }
    })

    if (!user) {
      throw new ApiError(404, "user not found")
    }

    const accessToken = generateAccessToken(user)
    const refreshToken = generateRefreshToken(user)

    user.refreshToken = refreshToken

    await prisma.user.update({
      where: {
        id: userId
      },
      data: {
        refreshToken: refreshToken
      }
    })

    return { accessToken, refreshToken }

  } catch (error) {

    throw new ApiError(500, "something went wrong while generating access token and refresh token")
  }

}

// signup
const registerUser = async (req: Request, res: Response) => {
  const { name, email, password } = req.body

  // check if user already exist before saving in db
  const existUser = await prisma.user.findFirst({
    where: {
      email: email
    }
  })

  if (existUser) {
    throw new ApiError(409, "User already exist with this email")
  }

  // hash the password before saving in the db
  const hashedPassword = await passwordHashing(password)

  const user = await prisma.user.create({
    data: {
      name: name,
      email: email,
      password: hashedPassword
    }
  })

  const createdUser = await prisma.user.findUnique({
    where: {
      id: user.id
    },
    select: {
      name: true,
      email: true,
    }
  })


  return res.status(201).json(
    new ApiResponse(200, createdUser, "User registered successfully!")
  )
}


// login the user
const loginUser = asyncHandler(
  async (req: Request, res: Response) => {
    const { email, password } = req.body

    if (!email) {
      throw new ApiError(400, "email is required for login")
    }

    const user = await prisma.user.findUnique({
      where: {
        email: email,
      }
    })

    if (!user) {
      throw new ApiError(404, "User does not exist!")
    }

    const isPasswordValid = await passwordChecking(password, user.password)

    if (!isPasswordValid) {
      throw new ApiError(400, "Incorrect password")
    }
    // if exist then return data with access token and refresh 
    const { accessToken, refreshToken } = await generateAccessAndRefreshToken(user.id)

    const loggedInUser = await prisma.user.findUnique({
      where: {
        id: user.id
      },
      select: {
        name: true,
        email: true
      }
    })

    // making cookie
    const option = {
      httpOnly: true,
      secure: true
    }
    console.log(req.cookies)

    return res.status(200)
      .cookie("accessToken", accessToken, option)
      .cookie("refreshToken", refreshToken, option)
      .json(
        new ApiResponse(
          200,
          {
            user: loggedInUser, accessToken
          },
          "User logged in successfully"
        )
      )
  }
)

const logoutUser = asyncHandler(async (req:Request,res:Response)=>{
  await prisma.user.update({
    where:{id:req.user.id},
    data:{refreshToken:null}
  })

  const options = {
    httpOnly:true,
    secure:true
  }

  return res.status(200).
  clearCookie("accessToken",options).clearCookie("refreshToken",options).json(
    new ApiResponse(200, {},"User logged out successfully")
  )
})

export {
  registerUser,
  loginUser,
  logoutUser
}