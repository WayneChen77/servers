const path = require("path");
const fs = require("fs");
const jsonServer = require("json-server");
const server = jsonServer.create();
const router = jsonServer.router(path.join(__dirname, "db.json"));

// const router = jsonServer.router("mock-api/db.json");
const middlewares = jsonServer.defaults();
const jwt = require("jsonwebtoken");
const port = process.env.PORT || 8000;
const { verify, Verify } = require("crypto");
const { decode } = require("punycode");

server.use(jsonServer.bodyParser);
server.use(middlewares);
server.use("/api", router);
server.listen(port);
//取得auther資料
const getAutherDb = () => {
  return JSON.parse(
    fs.readFileSync(path.join(__dirname, "auther.json"), "UTF-8")
  );
};

//判斷是否使用者  重複
const isAuther = ({ email, password }) => {
  return (
    getAutherDb().users.findIndex(
      (user) => user.email === email && user.password === password
    ) !== -1
  );
};
const isAuther1 = ({ email }) => {
  return getAutherDb().users.findIndex((user) => user.email === email) !== -1;
};
//上面程式 findIndex會回傳資料的位置 資料位置為X 所已存在的話 會大於-1
const secret = "jyj161";
//宣告jwt利用函式
const token = (data) => jwt.sign(data, secret, { expiresIn: "1h" });

//請求
server.post("/auther/login", (req, res) => {
  const { email, password } = req.body;

  if (isAuther({ email, password })) {
    //取得使用者資料
    const user = getAutherDb().users.find(
      (u) => u.email === email && u.password === password
    );
    const { nickName, type, current, id } = user;
    //jwt傳入資料送出
    const ID = id;
    const JwToken = token({ nickName, type, current, email });
    console.log("userlog");
    return res.status(200).json({ JwToken, nickName, current, email, ID });
  } else {
    const status = 404;
    const msg = "mail or password wrong";
    console.log("wrongpassuser");
    return res.status(status).json({ status, msg });
  }
});
//修改使用者資料
//之後再用跳過
// server.patch("/auther/Users/", (req, res) => {
//   const { id, email, nickName, password } = req.body;
//   if (isAuther({ email, password })) {
//     //取得使用者資料
//     const user = getAutherDb().users.find(
//       (u) => u.email === email && u.password === password
//     );
//     user.
//     const { nickName, type, current, id } = user;

//   }
// });

//註冊
//有bug先使用js網指直接更改
server.post("/auther/register", (req, res) => {
  const { email, password, nickName, current, type } = req.body;

  if (isAuther1({ email })) {
    const status = 500;
    const msg = "email already exists";
    return res.status(status).json({ status, msg });
  }

  fs.readFile(path.join(__dirname, "auther.json"), (err, _data) => {
    if (err) {
      const status = 401;
      const msg = err;

      return res.status(status).json({ status, msg });
    }

    //get user data

    const data = JSON.parse(_data.toString());

    //get last user id
    const last_id = data.users[data.users.length - 1].id;
    //add new user
    data.users.push({
      id: last_id + 1,
      nickName,
      email,
      password,
      current,
      type,
    });

    fs.writeFile(
      path.join(__dirname, "auther.json"),
      JSON.stringify(data),
      (err, result) => {
        if (err) {
          const status = 401;
          const msg = err;
          res.status(status).json({ status, msg });
          console.log(5);
          return;
        }
      }
    );
  });
  // token return

  const JwToken = token({ nickName, type, current, email });
  res.status(200).json({ JwToken, email, nickName, current });
});
//herder token
server.use("/carts", (req, res, next) => {
  if (
    req.headers.authorization === undefined ||
    req.headers.authorization.split(" ")[0] !== `bearer`
  ) {
    const status = 401;
    msg = "error authorization";
    res.status(status).json({ status, msg });
    return;
  }
  try {
    const veriyTokenResult = verifyToken(
      req.headers.authorization.split(" ")[1]
    );

    if (veriyTokenResult instanceof Error) {
      const status = 401;
      msg = "access token not provided";
      res.status(status).json({ status, msg });
      return;
    }
    next();
  } catch (err) {
    const status = 401;
    msg = "error token is revoked";
    res.status(status).json({ status, msg });
  }
});
//verrify token
const verifyToken = (token) => {
  jwt.verify(token, secret, (err, decode) =>
    decode !== undefined ? decode : err
  );
};

server.use(router);
server.listen(port, () => {
  console.log("JSON Server is running");
});
