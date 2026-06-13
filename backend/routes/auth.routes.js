const express = require("express");
const router  = express.Router();
const {
  signup,
  activateAccount,
  resendActivation,
  login,
  refreshToken,
  logout,
} = require("../controllers/auth.controller");
const { protect }         = require("../middleware/auth.middleware");
const { captureMetadata } = require("../middleware/metadata.middleware");

router.use(captureMetadata);

router.post("/signup",             signup);
router.get("/activate",            activateAccount);   // GET /api/auth/activate?token=xxx
router.post("/resend-activation",  resendActivation);
router.post("/login",              login);
router.post("/refresh",            refreshToken);
router.post("/logout",   protect,  logout);

module.exports = router;
