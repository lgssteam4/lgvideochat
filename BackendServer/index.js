const express = require("express");
const dotenv = require("dotenv");
const userRouter = require("./routes/user");

const app = express();
const port = 3000;


app.use(express.json());

app.use(
  express.urlencoded({
    extended: true,
  })
);

app.use("/users", userRouter);

/* Error handler middleware */
app.use((err, req, res, next) => {
  const statusCode = err.statusCode || 500;
  console.error(err.message, err.stack);
  res.status(statusCode).json({ message: err.message });
  return;
});

app.get("/", (req, res) => {
  res.json({ message: "ok" });
});

app.listen(port, () => {
  console.log(`LGE backend listening at http://localhost:${port}`);
});
