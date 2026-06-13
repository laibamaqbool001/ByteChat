const express = require("express");
const router = express.Router();
const { initiateCall, updateCallStatus, getCallHistory } = require("../controllers/call.controller");
const { protect } = require("../middleware/auth.middleware");
const { captureMetadata } = require("../middleware/metadata.middleware");

router.use(protect, captureMetadata);

router.post("/",              initiateCall);
router.patch("/:callId",      updateCallStatus);
router.get("/history",        getCallHistory);

module.exports = router;