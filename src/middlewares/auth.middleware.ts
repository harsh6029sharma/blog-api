import type { Request, Response, NextFunction } from "express"
import { ApiError } from "../utils/ApiError"
import jwt from 'jsonwebtoken'
import type { JwtPayload } from "jsonwebtoken"
import { prisma } from "../db/db"

interface DecodedUser {
    id:number,
    email:string
}

declare global {
    namespace Express {
        interface Request {
            user: JwtPayload
        }
    }
}

const verifyJwt = async (req: Request, _: Response, next: NextFunction) => {
    try {
        const token = req.cookies?.accessToken

        if (!token) {
            throw new ApiError(401, "Unauthorized request")
        }

        const access_secret = process.env.ACCESS_TOKEN_SECRET

        if (!access_secret) {
            throw new ApiError(500, "access token secret missing")
        }

        const decodedToken = jwt.verify(token, access_secret) as DecodedUser

        const user = await prisma.user.findUnique({
            where:{
                id:decodedToken.id
            }
        })

        if(!user){
            throw new ApiError(401,"User not found")
        }

        req.user = decodedToken

        next()

    } catch (error) {

        throw new ApiError(401, "no decoded token found")

    }
}


export { verifyJwt }