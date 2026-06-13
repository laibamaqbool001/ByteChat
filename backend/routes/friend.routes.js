const express = require("express");
const router = express.Router();
const {
  sendRequest,
  acceptRequest,
  declineRequest,
  cancelRequest,
  removeFriend,
  blockUser,
  unblockUser,
  getPendingRequests,
} = require("../controllers/friend.controller");
const { protect } = require("../middleware/auth.middleware");
const { captureMetadata } = require("../middleware/metadata.middleware");

router.use(protect, captureMetadata);

router.get("/requests", getPendingRequests);
router.post("/request", sendRequest);                              // POST { username }
router.patch("/request/:requestId/accept", acceptRequest);
router.patch("/request/:requestId/decline", declineRequest);
router.patch("/request/:requestId/cancel", cancelRequest);
router.delete("/remove", removeFriend);                           // DELETE { username }
router.post("/block", blockUser);                                  // POST { username }
router.post("/unblock", unblockUser);                              // POST { username }

module.exports = router;
