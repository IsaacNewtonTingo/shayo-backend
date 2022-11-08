const express = require("express");
const router = express.Router();
const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");
require("dotenv").config();

const User = require("../models/user");
const UserVerification = require("../models/user-verification");
const PasswordReset = require("../models/password-reset");

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
    html: `<p>Hello,<br/>Verify your email to complete your signup process.<br/>Here is your verification code: <h2>${confirmationCode}</h2><br/>The code expires in the next 1hr.</p>`,
  };

  const saltRounds = 10;
  bcrypt
    .hash(confirmationCode, saltRounds)
    .then((hashedConfirmationCode) => {
      const newVerification = new UserVerification({
        userID: _id,
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
                data: _id,
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
router.post("/verify-email/:id", async (req, res) => {
  let { confirmationCode } = req.body;
  let userID = req.params.id;

  confirmationCode = confirmationCode.trim();
  userID = userID.trim();

  UserVerification.find({ userID })
    .then(async (response) => {
      if (response.length > 0) {
        //records found
        //check if code has expired
        const { expiresAt } = response[0];
        const hashedCode = response[0].confirmationCode;

        if (expiresAt < Date.now()) {
          //Has expired so delete
          await UserVerification.deleteMany({ userID })
            .then(async () => {
              await User.deleteOne({ _id: userID })
                .then(() => {
                  res.json({
                    status: "Failed",
                    message:
                      "The code you entered has already expired. Please sign up again",
                  });
                })
                .catch((err) => {
                  console.log(err);
                  res.json({
                    status: "Failed",
                    message: "Error occured while deleting expired user",
                  });
                });
            })
            .catch((err) => {
              console.log(err);
              res.json({
                status: "Failed",
                message: "Error occured while deleting expired code",
              });
            });
        } else {
          //has not expired
          //decrypt the code
          await bcrypt
            .compare(confirmationCode, hashedCode)
            .then(async (response) => {
              if (response) {
                //delete record
                await UserVerification.deleteMany({ userID })
                  .then(async () => {
                    //update user records
                    await User.updateOne({ _id: userID }, { verified: true })
                      .then(() => {
                        res.json({
                          status: "Success",
                          message:
                            "Email confirmed successfully. You can login",
                        });
                      })
                      .catch((err) => {
                        console.log(err);
                        res.json({
                          status: "Failed",
                          message: "Error occured while updating user records",
                        });
                      });
                  })
                  .catch((err) => {
                    console.log(err);
                    res.json({
                      status: "Failed",
                      message: "Error occured while deleting confirmed code",
                    });
                  });
              } else {
                res.json({
                  status: "Failed",
                  message: "Invalid code",
                });
              }
            })
            .catch((err) => {
              console.log(err);
              res.json({
                status: "Failed",
                message: "Error occured while comparing codes",
              });
            });
        }
      } else {
        //no records found
        res.json({
          status: "Failed",
          message: "No email verification records found",
        });
      }
    })
    .catch((err) => {
      console.log(err);
      res.json({
        status: "Failed",
        message: "Error occured finding verification records",
      });
    });
});

//resend code
router.post("/resend-email-verification-code/:id", async (req, res) => {
  //check if user has already created account
  const userID = req.params.id;
  await User.findOne({ _id: userID })
    .then(async (userResponse) => {
      if (userResponse) {
        //user found
        //check preexisting code and delate
        await UserVerification.findOneAndDelete({ userID })
          .then((response) => {
            if (response) {
              //records found and deleted
              //send new code and save
              sendVerificationEmail(userResponse, res);
            } else {
              //no record found
              res.json({
                status: "Failed",
                message: "User verification records not found.Please signup",
              });
            }
          })
          .catch((err) => {
            console.log(err);
            res.json({
              status: "Failed",
              message: "Error occured while getting user verification records",
            });
          });
      } else {
        //no user
        res.json({
          status: "Failed",
          message: "User not found. Please create an account",
        });
      }
    })
    .catch((err) => {
      console.log(err);
      res.json({
        status: "Failed",
        message: "Error occured while checking user records",
      });
    });
});

//login
router.post("/signin", (req, res) => {
  console.log("Connected");
  let { email, password } = req.body;
  email = email.trim();
  password = password.trim();

  if (!email || !password) {
    res.json({
      status: "Failed",
      message: "All fields are required",
    });
  } else {
    User.find({ email })
      .then((data) => {
        if (data.length) {
          if (!data[0].verified) {
            res.json({
              status: "Failed",
              message: "Email hasn't been verified",
            });
          } else {
            const hashedPassword = data[0].password;
            const userData = [{ _id: data[0]._id }];

            bcrypt
              .compare(password, hashedPassword)
              .then(async (result) => {
                if (result) {
                  res.json({
                    status: "Success",
                    message: "Login successfull",
                    data: userData,
                  });
                } else {
                  res.json({
                    status: "Failed",
                    message: "Invalid password",
                  });
                }
              })
              .catch((err) => {
                console.log(err);
                res.json({
                  status: "Failed",
                  message: "Error occured while comparing passwords",
                });
              });
          }
        } else {
          res.json({
            status: "Failed",
            message: "Invalid credentials entered",
          });
        }
      })
      .catch((err) => {
        res.json({
          status: "Failed",
          message: "Error occured checking existing user",
        });
      });
  }
});

//password reset
router.post("/request-password-reset", (req, res) => {
  const { email, redirectUrl } = req.body;

  if (!email) {
    res.json({
      status: "Failed",
      message: "Please input email",
    });
  } else {
    User.find({ email })
      .then((data) => {
        if (data.length) {
          if (!data[0].verified) {
            res.json({
              status: "Failed",
              message: "Email hasn't been verified yet. Check your email",
            });
          } else {
            sendResetEmail(data[0], redirectUrl, res);
          }
        } else {
          res.json({
            status: "Failed",
            message: "No account with the given email exists",
          });
        }
      })
      .catch((err) => {
        res.json({
          status: "Failed",
          message: "Error occured whie checking existing user",
        });
      });
  }
});

const sendResetEmail = ({ _id, email }, redirectUrl, res) => {
  const resetString = Math.floor(1000 + Math.random() * 9000).toString();

  PasswordReset.deleteMany({ userId: _id })
    .then((result) => {
      const mailOptions = {
        from: process.env.AUTH_EMAIL,
        to: email,
        subject: "Reset your password",
        html: `<p>You have initiated a reset password process.</p><p>Code <b>expires in 60 minutes</p> <p>Here is your secret code:</p><p><strong>${resetString}</strong><br/>Enter the code in the app, with your new password.</p>`,
      };

      const saltRounds = 10;
      bcrypt
        .hash(resetString, saltRounds)
        .then((hashedResetString) => {
          const newPasswordReset = new PasswordReset({
            userId: _id,
            resetString: hashedResetString,
            createdAt: Date.now(),
            expiresAt: Date.now() + 3600000,
          });

          newPasswordReset
            .save()
            .then(() => {
              transporter
                .sendMail(mailOptions)
                .then(() => {
                  res.json({
                    status: "Pending",
                    message: _id,
                  });
                })
                .catch((err) => {
                  res.json({
                    status: "Failed",
                    message: "Error sending password reset email",
                  });
                });
            })
            .catch((err) => {
              console.log(err);
              res.json({
                status: "Failed",
                message: "Error occured saving reset record",
              });
            });
        })
        .catch((err) => {
          console.log(err);
          res.json({
            status: "Failed",
            message: "Error while hashing password reset data",
          });
        });
    })
    .catch((err) => {
      console.log(err);
      res.json({
        status: "Failed",
        message: "Error while clearing past records",
      });
    });
};

//reset password
router.post("/reset-password", (req, res) => {
  let { userId, resetString, newPassword } = req.body;
  userId = userId.trim();
  resetString = resetString.trim();
  newPassword = newPassword.trim();

  PasswordReset.find({ userId })
    .then((result) => {
      if (result.length > 0) {
        const { expiresAt } = result[0];
        const hashedResetString = result[0].resetString;

        if (expiresAt < Date.now()) {
          PasswordReset.deleteOne({ userId })
            .then(() => {
              res.json({
                status: "Failed",
                message: "Password reset link has expired",
              });
            })
            .catch((err) => {
              console.log(err);
              res.json({
                status: "Failed",
                message: "Failed to delete outdated password reset record",
              });
            });
        } else {
          bcrypt
            .compare(resetString, hashedResetString)
            .then((result) => {
              if (result) {
                const saltRounds = 0;
                bcrypt
                  .hash(newPassword, saltRounds)
                  .then((hashedNewPassword) => {
                    User.updateOne(
                      { _id: userId },
                      { password: hashedNewPassword }
                    )
                      .then(() => {
                        PasswordReset.deleteOne({ userId })
                          .then(() => {
                            res.json({
                              status: "Success",
                              message:
                                "You have successfully reset your password",
                            });
                          })
                          .catch((err) => {
                            console.log(err);
                            res.json({
                              status: "Failed",
                              message:
                                "An error occured while finalizing password reset",
                            });
                          });
                      })
                      .catch((err) => {
                        console.log(err);
                        res.json({
                          status: "Failed",
                          message: "Updating user password failed",
                        });
                      });
                  })
                  .catch((err) => {
                    console.log(err);
                    res.json({
                      status: "Failed",
                      message: "An error occured while hashing new password",
                    });
                  });
              } else {
                res.json({
                  status: "Failed",
                  message: "Invalid password reset details passed",
                });
              }
            })
            .catch((err) => {
              console.log(err);
              res.json({
                status: "Failed",
                message: "Comparing password reset string failed failed",
              });
            });
        }
      } else {
        res.json({
          status: "Failed",
          message: "Password reset request not found",
        });
      }
    })
    .catch((err) => {
      console.log(err);
      res.json({
        status: "Failed",
        message: "Checking for checking reset record failed",
      });
    });
});

module.exports = router;
