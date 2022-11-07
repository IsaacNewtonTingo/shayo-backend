const express = require("express");
const User = require("../models/user");
const UserVerification = require("../models/user-verification");
const router = express.Router();
const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");
require("dotenv").config();

let transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.AUTH_EMAIL,
    pass: process.env.AUTH_PASS,
  },
});

//signup
router.post("/signup", async (req, res) => {
  let {
    firstName,
    lastName,
    email,
    phoneNumber,
    password,
    generalPromotedTitle,
  } = req.body;

  firstName = firstName.trim();
  lastName = lastName.trim();
  email = email.trim();
  phoneNumber = phoneNumber.toString().trim();
  password = password.trim();
  generalPromotedTitle = generalPromotedTitle
    ? generalPromotedTitle.trim()
    : "";

  if (!firstName || !lastName || !email || !phoneNumber || !password) {
    res.json({
      status: "Failed",
      message: "All fields are required",
    });
  } else if (!/^[a-zA-Z ]*$/.test(firstName, lastName)) {
    res.json({
      status: "Failed",
      message: "Invalid name format",
    });
  } else if (!/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/.test(email)) {
    res.json({
      status: "Failed",
      message: "Invalid email",
    });
  } else if (password.length < 8) {
    res.json({
      status: "Failed",
      message: "Password is too short",
    });
  } else {
    await User.find({ $or: [{ email }, { phoneNumber }] })
      .then((result) => {
        if (result.length) {
          res.json({
            status: "Failed",
            message: "User with the given email/phone number already exists",
          });
        } else {
          const salt = 10;
          bcrypt
            .hash(password, salt)
            .then((hashedPassword) => {
              const newUser = new User({
                firstName,
                lastName,
                email,
                phoneNumber: parseInt(phoneNumber),
                password: hashedPassword,
                verified: false,

                bio: "",
                location: "",
                profilePicture: "",
                isFeatured: false,
                dateFeatured: "",
                dateExpiring: "",
              });
              newUser
                .save()
                .then((result) => {
                  //Send email
                  sendVerificationEmail(result, res);
                })
                .catch((err) => {
                  console.log(err);
                  res.json({
                    status: "Failed",
                    message: "Error occured while creating account",
                  });
                });
            })
            .catch((err) => {
              console.log(err);
              res.json({
                status: "Failed",
                message: "Error occured while hashing password",
              });
            });
        }
      })
      .catch((err) => {
        console.log(err);
        res.json({
          status: "Failed",
          message: "Error occured when checking email and phoneNumber",
        });
      });
  }
});

//send code to email
const sendVerificationEmail = ({ _id, email }, res) => {
  const confirmationCode = Math.floor(1000 + Math.random() * 9000).toString();

  const mailOptions = {
    from: process.env.AUTH_EMAIL,
    to: email,
    subject: "Verify your email",
    html: `<p>Hello.<br/>Verify your email to complete your signup process.<br/>Here is your verification code: <h2>${confirmationCode}</h2><br/>The code expires in the next 1hr.</p>`,
  };

  const saltRounds = 10;
  bcrypt
    .hash(confirmationCode, saltRounds)
    .then((hashedConfirmationCode) => {
      const newVerification = new UserVerification({
        userId: _id,
        confirmationCode: hashedConfirmationCode,
        createdAt: Date.now(),
        expiresAt: Date.now() + 3600000,
      });
      newVerification
        .save()
        .then(() => {
          transporter
            .sendMail(mailOptions)
            .then(() => {
              res.json({
                status: "Pending",
                message: "Verification email sent",
              });
            })
            .catch((err) => {
              console.log(err);
              res.json({
                status: "Failed",
                message: "Error occured sending verification email",
              });
            });
        })
        .catch((err) => {
          console.log(err);
          res.json({
            status: "Failed",
            message: "Couldn't save verification email data",
          });
        });
    })
    .catch((err) => {
      console.log(err);
      res.json({
        status: "Failed",
        message: "Error occured hashing email data",
      });
    });
};

//email verification code validation
router.post("/verify-email-code", async (req, res) => {});

module.exports = router;
