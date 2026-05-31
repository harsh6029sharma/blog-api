import type { Request, Response } from "express"
import { prisma } from '../db/db'
import { ApiResponse } from "../utils/ApiResponse"
import { ApiError } from "../utils/ApiError"
import { generateAccessToken, generateRefreshToken, passwordChecking, passwordHashing } from "../utils/auth"
import asyncHandler from '../utils/asyncHandler'
import jwt from "jsonwebtoken"
import bcrypt from 'bcrypt'
import crypto from 'crypto'
import { transporter } from "../utils/mail"

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


const logoutUser = asyncHandler(async (req: Request, res: Response) => {
  await prisma.user.update({
    where: { id: req.user.id },
    data: { refreshToken: null }
  })

  const options = {
    httpOnly: true,
    secure: true
  }

  return res.status(200).
    clearCookie("accessToken", options).clearCookie("refreshToken", options).json(
      new ApiResponse(200, {}, "User logged out successfully")
    )
})


const refreshAccessToken = asyncHandler(async (req: Request, res: Response) => {

  const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken

  if (!incomingRefreshToken) {
    throw new ApiError(401, "refresh token is missing")
  }

  try {
    const decoded = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET!) as any

    const user = await prisma.user.findUnique({
      where: {
        id: decoded.id
      }
    })

    if (!user) {
      throw new ApiError(404, "user not found")
    }

    if (user.refreshToken !== incomingRefreshToken) {
      throw new ApiError(401, "Invalid refresh token")
    }

    const newAccessToken = generateAccessToken(user) as string

    const options = {
      httpOnly: true,
      secure: true
    }

    return res.cookie("accessToken", newAccessToken, options)
      .json(
        new ApiResponse(200, "access token refreshed")
      )

  } catch (error) {
    throw new ApiError(401, "Internal refresh token")
  }

})

const getCurrentUser = asyncHandler(async (req: Request, res: Response) => {

  const userId = req.user.id
  if (!userId) {
    throw new ApiError(404, "User id is missing or not found")
  }

  // const {id} = req.user

  const currentUser = await prisma.user.findUnique({
    where: {
      id: userId
    }
  })

  return res.status(200).json(
    new ApiResponse(200, currentUser, "current user found successfully")
  )
})

const changePassword = asyncHandler(async (req: Request, res: Response) => {

  const userId = req.user.id    //req.user = decodedToken

  const user = await prisma.user.findUnique({
    where: {
      id: userId
    }
  })

  if (!user) {
    throw new ApiError(404, "User not found")
  }

  const { oldPassword, newPassword } = req.body

  if (!oldPassword || !newPassword) {
    throw new ApiError(400, "All fields are required")
  }

  const isPasswordCorrect = await bcrypt.compare(oldPassword, user.password)

  if (!isPasswordCorrect) {
    throw new ApiError(401, "Invalid old password")
  }

  const isSamePassword = await bcrypt.compare(newPassword, user.password)

  if (isSamePassword) {
    throw new ApiError(400, "new password cannot be same as old password")
  }

  const hashedNewPassword = await bcrypt.hash(newPassword, 10)

  await prisma.user.update({
    where: {
      id: userId
    },
    data: {
      password: hashedNewPassword
    }
  })

  return res.status(200).json(
    new ApiResponse(200, {}, "password changed successfully")
  )

})


const forgotPassword = asyncHandler(async (req: Request, res: Response) => {
  // enter email
  const { email } = req.body

  // user of this email
  const user = await prisma.user.findUnique({
    where: {
      email: email
    }
  })

  if (!user) {
    throw new ApiResponse(200, {}, "if email exists, reset email sent")
  }

  // generating secure token
  const resetToken = crypto.randomBytes(32).toString("hex")
  const hashedToken = crypto.createHash("sha256").update(resetToken).digest("hex")

  // save hashed token in db
  await prisma.user.update({
    where: {
      email: email
    },
    data: {
      resetPasswordToken: hashedToken,
      resetPasswordExpiry: new Date(Date.now() + 10 * 60 * 1000)  // after 10 minutes it expires
    }
  })

  // send email
  const resetUrl = `http://localhost:3000/reset-password/${resetToken}`

  try {
    await transporter.sendMail({
      to: user.email,
      subject: "Password Reset",
      html: `
        <h1>Reset Password</h1>
        <a href="${resetUrl}">Reset Password</a>
      `
    })

    return res.status(200).json(
      new ApiResponse(200, {resetToken:resetToken}, "Reset password link sent")
    )
  } catch (error) {

    // cleanup the tokens if email could not send
    await prisma.user.update({
      where: {
        email: email
      },
      data: {
        resetPasswordToken: null,
        resetPasswordExpiry: null
      }
    })
    throw new ApiError(500, "password reset link email couldn't send")

  }


})

const resetPassword = asyncHandler( async (req:Request, res:Response)=>{
  const token = req.params.token as string
  console.log(req.params)
  const {newPassword} = req.body

  // hash incoming token
  const hashedToken = crypto
    .createHash("sha256")
    .update(token)
    .digest("hex")

  // find user with valid token
  const user = await prisma.user.findFirst({
    where:{
      resetPasswordToken:hashedToken,
      resetPasswordExpiry:{
        gt:new Date()
      }
    }
  })

  if(!user){
    throw new ApiError(400, "Invalid or expired token ")
  }

  // hash the new password
  const hashedNewPassword = await bcrypt.hash(newPassword, 10)

  await prisma.user.update({
    where:{
      id:user.id
    },
    data:{
      password:hashedNewPassword,
      resetPasswordToken:null,
      resetPasswordExpiry:null
    }
  })

  return res.status(200).json(
    new ApiResponse(200, {}, "password reset successfully")
  )

} )


const updateAccountDetails = asyncHandler( async(req:Request, res:Response)=>{
  const {decodeToken} = req.user

  const userId = decodeToken.id

  const user = await prisma.user.findUnique({
    where:{
      id:userId
    }
  })

  console.log(user)
} )

export {
  registerUser,
  loginUser,
  logoutUser,
  refreshAccessToken,
  getCurrentUser,
  changePassword,
  forgotPassword,
  resetPassword,
  updateAccountDetails
}