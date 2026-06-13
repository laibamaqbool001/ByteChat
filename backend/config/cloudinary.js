const cloudinary = require("cloudinary").v2;
const { CloudinaryStorage } = require("multer-storage-cloudinary");
const multer = require("multer");
const streamifier = require("streamifier");

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key:    process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// ── Multer middleware (memory storage — gives us req.file.buffer) ──
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }, // 10 MB
  fileFilter: (req, file, cb) => {
    const allowed = ["image/jpeg", "image/png", "image/webp"];
    if (!allowed.includes(file.mimetype)) {
      return cb(new Error("Only JPEG, PNG, and WebP images are allowed"), false);
    }
    cb(null, true);
  },
});

/**
 * Upload a raw Buffer to Cloudinary.
 * Used by message.controller.js for image messages and edits.
 *
 * @param {Buffer} buffer   - Raw image bytes from req.file.buffer
 * @param {string} folder   - Cloudinary folder path  e.g. "bytechat/messages"
 * @returns {Promise<object>} Cloudinary upload result (secure_url, public_id, etc.)
 */
const uploadToCloudinary = (buffer, folder = "bytechat/messages") => {
  return new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(
      {
        folder,
        resource_type: "image",
        allowed_formats: ["jpg", "jpeg", "png", "webp"],
      },
      (error, result) => {
        if (error) return reject(error);
        resolve(result);
      }
    );
    // Pipe the buffer into the Cloudinary upload stream
    streamifier.createReadStream(buffer).pipe(stream);
  });
};

module.exports = { cloudinary, upload, uploadToCloudinary };
