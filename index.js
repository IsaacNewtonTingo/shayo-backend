const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser").json;
require("dotenv").config();

const app = express();

app.use(cors());
app.use(bodyParser());

const PORT = process.env.PORT;

app.listen(PORT, () => {
  console.log(`App listening on port ${PORT}`);
});

require("./config/db");

const UserRouter = require("./routes/user");

app.use("/user", UserRouter);
