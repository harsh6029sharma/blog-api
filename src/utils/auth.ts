import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import type { User } from './Types'
import { ApiError } from './ApiError'
import { verifyJwt } from '../middlewares/auth.middleware'

const passwordHashing = async(password:string):Promise<string> =>{
    const hashedPassword = await bcrypt.hash(password,10)
    return hashedPassword
}


const passwordChecking = async(password:string,hashedPassword:string):Promise<boolean> =>{
    return bcrypt.compare(password,hashedPassword)
}


const generateAccessToken = (data:User)=>{
    const secret = process.env.ACCESS_TOKEN_SECRET

    if(!secret){
        throw new ApiError(500, "ACCESS_TOKEN_SECRET is not defined in your environment variable")
    }
    const token = jwt.sign(
        // payload
        {
            id:data.id,
            email:data.email,
            name:data.name
        },
        secret,
        {
            expiresIn:'1d'
        }

    )
    return token
}

const generateRefreshToken = (data:User)=>{
    const secret = process.env.REFRESH_TOKEN_SECRET

    if(!secret){
        throw new ApiError(500, "REFRESH_TOKEN_SECRET is not defined in your environment variable")
    }
    const token = jwt.sign(
        // payload
        {
            id:data.id,
        },
        secret,
        {
            expiresIn:'10d'
        }

    )
    return token
}


export {
    passwordHashing,
    passwordChecking,
    generateAccessToken,
    generateRefreshToken
}