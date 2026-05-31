import { Router } from "express";
import { loginUser, registerUser, logoutUser, refreshAccessToken, getCurrentUser, changePassword, forgotPassword, resetPassword, updateAccountDetails } from "../controllers/user.controller";
import { verifyJwt } from "../middlewares/auth.middleware";

const router = Router()

// authentication routes
router.route("/register").post(registerUser)
router.route("/login").post(loginUser)
router.route("/refresh-token").post(refreshAccessToken)

// protected routes
router.route("/logout").post(verifyJwt,logoutUser)
router.route("/current-user").get(verifyJwt, getCurrentUser)
router.route("/change-password").patch(verifyJwt, changePassword)
router.route('/update-account').patch(verifyJwt, updateAccountDetails)

// forgot password routes
router.route("/forgot-password").post(forgotPassword)
router.route("/reset-password/:token").patch(resetPassword)

export default router