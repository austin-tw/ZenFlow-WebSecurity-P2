const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
  {
    googleId: { type: String, required: true, unique: true },
    username: { type: String, required: true },
    loginCount: { type: Number, default: 0 },
    role: { type: String, default: "user" }, // Possible roles: 'user', 'superuser'
  },
  { timestamps: true }
);

module.exports = mongoose.model("User", userSchema);
