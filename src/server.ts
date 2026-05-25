import express from 'express';
import { type Request, type Response } from 'express';
import cookieParser from 'cookie-parser'

const app = express()

const PORT = Number(process.env.PORT)||3000

// built-in middlewares for json body cookie parser
app.use(express.json({limit:"16kb"}))
app.use(express.urlencoded({extended:true, limit:"16kb"}))
app.use(express.static("public"))
app.use(cookieParser())

app.get("/",(req:Request,res:Response)=>{
    res.send("hello world")
})

app.listen(PORT, ()=>{
    console.log(`server is listening on port: ${PORT}`)
})