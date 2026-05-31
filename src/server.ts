import express from 'express';
import cookieParser from 'cookie-parser'
import dotenv from 'dotenv'

dotenv.config()

const app = express()

const PORT:number = Number(process.env.PORT)||3000

// built-in middlewares for json body cookie parser
app.use(express.json({strict:true}))
app.use(express.urlencoded({extended:true, limit:"16kb"}))
app.use(express.static("public"))
app.use(cookieParser())


// import routes
import userRouter from './routes/user.route'

app.use("/api/v1/users",userRouter)

app.listen(PORT, ()=>{
    console.log(`server is listening on port: ${PORT}`)
})