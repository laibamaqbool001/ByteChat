const express = require("express");
const router = express.Router();
const {
  generateReport,
  downloadReport,
  downloadReportJSON,
  verifyReport,
  getMessageCustody,
  getMyActivityLog,
  verifyConversationIntegrity,
  listMyReports,
} = require("../controllers/forensic.controller");
const { protect } = require("../middleware/auth.middleware");
const { captureMetadata } = require("../middleware/metadata.middleware");

router.use(protect, captureMetadata);

// Evidence reports
router.post("/reports", generateReport);                            // Generate new report
router.get("/reports", listMyReports);                             // List my reports
router.get("/reports/:reportId/download", downloadReport);         // Download PDF
router.get("/reports/:reportId/download/json", downloadReportJSON);// Download JSON
router.get("/reports/:reportId/verify", verifyReport);             // Verify report integrity

// Chain of custody
router.get("/messages/:messageId/custody", getMessageCustody);     // Message custody trail
router.get("/conversations/:username/integrity", verifyConversationIntegrity); // Batch tamper check

// Activity log
router.get("/activity", getMyActivityLog);                         // My audit log

module.exports = router;
