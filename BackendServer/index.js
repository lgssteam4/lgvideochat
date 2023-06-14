const express = require("express");
const dotenv = require("dotenv");
const https = require("https");
const fs = require("fs");
const path = require("path");
const router = require("./routes/user");

const app = express();
const port = process.env.PORT || 3000;


app.use(express.json());

app.use(
  express.urlencoded({
    extended: true,
  })
);

app.use("/api", router);

/* Error handler middleware */
app.use((err, req, res, next) => {
  const statusCode = err.statusCode || 500;
  console.error(err.message);
  console.error(err.stack);
  res.status(statusCode).json({ message: err.message });
  return;
});

app.get("/", (req, res) => {
  res.json({ message: "Welcome to LGE Chat Backend Server" });
});

const httpsServer = https.createServer(
	{
	key: fs.readFileSync(path.join(__dirname,
	    "certs", "lge-backend-key.pem")),
	cert: fs.readFileSync(path.join(__dirname,
	    "certs", "lge-backend-cert.pem")),
	},
	app 
)

httpsServer.listen(3001, () => {
    console.log("HTTPS server up and running on port 3001")
})
