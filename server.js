const bcrypt = require("bcrypt");
const bodyParser = require("body-parser");
const cors = require("cors");
const express = require("express");
const jsonwebtoken = require("jsonwebtoken");
const sqlite3 = require("sqlite3");
const multer = require("multer");

const upload = multer();
const app = express();
const port = 3001;

app.use(cors());
app.use(bodyParser.json());

const db = new sqlite3.Database("./db.db", (err) => {
  if (err) {
    return console.log(err);
  }
  return console.log("бд подключена");
});

function checkToken(token, res) {
  let id = 0;
  if (!token) {
    return res.status(500).json({ message: "Токен не предоставлен" });
  }

  jsonwebtoken.verify(token, "secret", (err, row) => {
    if (err) {
      return res.status(500).json({ message: "Не получилось верифицировать" });
    }
    id = row.userId;
  });
  return id;
}

app.post("/refresh", async (req, res) => {
  const id = checkToken(req.headers.authorization?.split(" ")[1], res);
  if (id) {
    db.get(`select * from users where id = ?`, [id], (err, row) => {
      if (err || !row) {
        return res.status(500).json({ message: err });
      }
      return res.status(200).send({
        token: jsonwebtoken.sign(
          { userId: row.id, name: row.username, isAdmin: row.isAdmin },
          "secret",
          { expiresIn: "1h" }
        ),
      });
    });
  } else {
    return res.status(500).send("Ошибка обновления токена");
  }
});

app.post("/register", async (req, res) => {
  const { username, password, email, phone } = req.body;

  if (!username || !password) {
    return res
      .status(400)
      .json({ message: "Все поля обязательны для заполнения" });
  }

  db.get(`select * from users where username = ?`, [username], (err, row) => {
    if (err) {
      return res.status(500).json({ message: err });
    }
    if (row) {
      return res
        .status(500)
        .json({ message: "Такой пользователь уже существует" });
    }
    const hash = bcrypt.hashSync(password, 10);
    db.run(
      "insert into users (username, password, isAdmin, email, phone, isSendedReview) values (?, ?, ?, ?, ?, ?)",
      [username, hash, 0, email, phone, 0],
      function (err) {
        if (err) {
          return res
            .status(500)
            .json({ message: "Не получилось создать пользователя" });
        }
        return res
          .status(200)
          .json({ message: "Получилось создать пользователя!" });
      }
    );
  });
});

app.post("/auth", async (req, res) => {
  const { email, password } = req.body;

  db.get(`select * from users where email = ?`, [email], (err, row) => {
    if (!row) {
      return res
        .status(500)
        .json({ message: "Такого пользователя не существует" });
    }
    const unHah = bcrypt.compareSync(password, row.password);
    if (err || !unHah) {
      return res.status(500).json({ message: err });
    }
    const token = jsonwebtoken.sign(
      { userId: row.id, name: row.username, isAdmin: row.isAdmin },
      "secret",
      { expiresIn: "1h" }
    );
    res.status(200).json({
      id: row.id,
      token,
      isAdmin: row.isAdmin,
      username: row.username,
      email: row.email,
      phone: row.phone,
    });
  });
});

app.post("/me", async (req, res) => {
  const id = checkToken(req.headers.authorization?.split(" ")[1], res);

  db.get(`select * from users where id = ?`, [id], (err, row) => {
    if (err) {
      return res.status(500).json({ message: err });
    }
    const token = jsonwebtoken.sign(
      { userId: row.id, name: row.username, isAdmin: row.isAdmin },
      "secret",
      { expiresIn: "1h" }
    );
    res.status(200).json({
      id: row.id,
      token,
      isAdmin: row.isAdmin,
      username: row.username,
      email: row.email,
      phone: row.phone,
      isSendedReview: row.isSendedReview,
    });
  });
});

app.post("/all-goods", async (req, res) => {
  const { type } = req.body;

  let sql = "select * from goods";
  let params = [];

  if (type && type !== "Все") {
    sql = "select * from goods where type = ?";
    params = [type];
  }

  db.all(sql, params, (err, rows) => {
    if (err || !rows) {
      return res
        .status(500)
        .json({ message: "Не получилось запросить товары" });
    }

    const data = rows.map((row) => {
      let imageBase64 = null;
      if (row.image) {
        imageBase64 = Buffer.from(row.image).toString("base64");
      }
      return {
        ...row,
        image: imageBase64,
      };
    });

    res.status(200).json({ data });
  });
});

app.post("/add-good", upload.single("image"), async (req, res) => {
  const { name, price, description, type, max } = req.body;
  const image = req.file;

  const id = checkToken(req.headers.authorization?.split(" ")[1], res);

  if (!id) return res.status(500).json({ message: "Неправильный токен" });

  db.run(
    "insert into goods (name, price, description, type, max, image) values (?, ?, ?, ?, ?, ?)",
    [name, price, description, type, max, image ? image.buffer : null],
    function (err) {
      if (err) {
        return res.status(500).json({ message: "Не получилось создать товар" });
      }
      return res.status(200).json({ message: "Получилось создать товар!" });
    }
  );
});

app.post("/change-good", upload.single("image"), async (req, res) => {
  const { id, name, price, description, type, max } = req.body;
  const image = req.file;

  const userId = checkToken(req.headers.authorization?.split(" ")[1], res);
  if (!userId) return res.status(401).json({ message: "Неправильный токен" });

  if (!id) return res.status(400).json({ message: "Не передан id товара" });

  let sql = "";
  let params = [];

  if (image) {
    sql =
      "UPDATE goods SET name=?, price=?, description=?, type=?, max=?, image=? WHERE id=?";
    params = [name, price, description, type, max, image.buffer, Number(id)];
  } else {
    sql =
      "UPDATE goods SET name=?, price=?, description=?, type=?, max=? WHERE id=?";
    params = [name, price, description, type, max, Number(id)];
  }

  db.run(sql, params, function (err) {
    if (err) {
      return res.status(500).json({ message: "Не удалось изменить товар" });
    }
    return res.status(200).json({ message: "Новость изменена!" });
  });
});

app.post("/all-requests", async (req, res) => {
  const { username } = req.body;
  let sql = "select * from requests";
  let params = [];

  if (username && username !== "Все") {
    sql = "select * from requests where username = ?";
    params = [username];
  }
  db.all(sql, params, (err, row) => {
    if (!row || err) {
      return res
        .status(500)
        .json({ message: "Не получилось запросить заказы" });
    }
    res.status(200).json(row);
  });
});

app.post("/add-requests", async (req, res) => {
  const { username, service, name, description, price, total } = req.body;

  const userId = checkToken(req.headers.authorization?.split(" ")[1], res);
  if (!userId) return res.status(401).json({ message: "Неправильный токен" });

  db.run(
    "insert into requests (username, service, name, description, price, total) values (?, ?, ?, ?, ?, ?)",
    [username, service, name, description, price, total],
    function (err) {
      if (err) {
        return res.status(500).json({ message: "Не получилось создать заказ" });
      }
      return res.status(200).json({ message: "Получилось создать заказ!" });
    }
  );
});

app.post("/add-another-requests", async (req, res) => {
  const { username, service, phone } = req.body;

  db.run(
    "insert into another_requests (username, service, phone) values (?, ?, ?)",
    [username, service, phone],
    function (err) {
      if (err) {
        return res.status(500).json({ message: "Не получилось записаться" });
      }
      return res
        .status(200)
        .json({ message: "Получилось создать записаться!" });
    }
  );
});

app.post("/get-another-requests", async (req, res) => {
  const { username } = req.body;
  let sql = "select * from another_requests";
  let params = [];

  if (username && username !== "Все") {
    sql = "select * from another_requests where username = ?";
    params = [username];
  }
  db.all(sql, params, (err, row) => {
    if (!row || err) {
      return res
        .status(500)
        .json({ message: "Не получилось запросить записи" });
    }
    res.status(200).json(row);
  });
});

app.post("/delete-good", async (req, res) => {
  const { id } = req.body;

  const userId = checkToken(req.headers.authorization?.split(" ")[1], res);
  if (!userId) return res.status(401).json({ message: "Неправильный токен" });

  if (!id) return res.status(400).json({ message: "Не передан id товара" });

  db.run("DELETE FROM requests WHERE id=?", [Number(id)], function (err) {
    if (err) {
      return res.status(500).json({ message: "Не удалось удалить товар" });
    }
    return res.status(200).json({ message: "Товар удалена!" });
  });
});

app.post("/delete-request", async (req, res) => {
  const { id } = req.body;

  const userId = checkToken(req.headers.authorization?.split(" ")[1], res);
  if (!userId) return res.status(401).json({ message: "Неправильный токен" });

  if (!id) return res.status(400).json({ message: "Не передан id услуги" });

  db.run(
    "DELETE FROM another_requests WHERE id=?",
    [Number(id)],
    function (err) {
      if (err) {
        return res.status(500).json({ message: "Не удалось удалить услугу" });
      }
      return res.status(200).json({ message: "Услуга удалена!" });
    }
  );
});

app.post("/send-review", async (req, res) => {
  const { username, text, review } = req.body;

  const userId = checkToken(req.headers.authorization?.split(" ")[1], res);
  if (!userId) return res.status(401).json({ message: "Неправильный токен" });

  db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, row) => {
    if (err || !row) {
      return res.status(404).json({ message: "Пользователь не найден" });
    }

    db.run(
      `UPDATE users SET isSendedReview = 1 WHERE username = ?`,
      [username],
      (err) => {
        if (err) {
          return res
            .status(500)
            .json({ message: "Ошибка обновления пользователя" });
        }

        db.run(
          `INSERT INTO review (username, text, review) VALUES (?, ?, ?)`,
          [username, text, review],
          (err) => {
            if (err) {
              return res
                .status(500)
                .json({ message: "Ошибка сохранения отзыва" });
            }
            return res.status(200).json({ message: "Отзыв успешно отправлен" });
          }
        );
      }
    );
  });
});

app.post("/reviews", async (req, res) => {
  const { username } = req.body;
  let sql = "select * from review";
  let params = [];

  if (username && username !== "Все") {
    sql = "select * from review where username = ?";
    params = [username];
  }
  db.all(sql, params, (err, row) => {
    if (!row || err) {
      return res
        .status(500)
        .json({ message: "Не получилось запросить отзывы" });
    }
    res.status(200).json(row);
  });
});

app.post("/delete-review", async (req, res) => {
  const { id, username } = req.body;

  const userId = checkToken(req.headers.authorization?.split(" ")[1], res);
  if (!userId) return res.status(401).json({ message: "Неправильный токен" });

  if (!id) return res.status(400).json({ message: "Не передан id отзыва" });

  db.run(
    `UPDATE users SET isSendedReview = 0 WHERE username = ?`,
    [username],
    (err) => {
      if (err) {
        return res
          .status(500)
          .json({ message: "Ошибка обновления пользователя" });
      }
      db.run("DELETE FROM review WHERE id=?", [Number(id)], function (err) {
        if (err) {
          return res.status(500).json({ message: "Не удалось удалить отзыв" });
        }
        return res.status(200).json({ message: "Отзыв удалена!" });
      });
    }
  );
});
app.listen(port, () => console.log(`http://localhost:${port}`));
