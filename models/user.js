const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const UserSchema = new Schema({
  firstName: String,
  lastName: String,
  email: String,
  phoneNumber: Number,
  profilePicture: String,
  bio: String,
  location: String,
  password: String,
  verified: Boolean,
  isFeatured: Boolean,
  generalPromotedTitle: String,
  dateFeatured: Date,
  dateExpiring: Date,
});

const User = mongoose.model("User", UserSchema);
module.exports = User;
