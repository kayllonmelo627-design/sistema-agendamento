const express = require("express");
const cors = require("cors");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const SECRET = "segredo-super-seguro";

app.use(cors());
app.use(express.json());
app.use(express.static("public"));

// Banco de dados
const db = new sqlite3.Database("banco.db");

// Criar tabelas
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario TEXT UNIQUE,
    senha TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS agendamentos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nome TEXT,
    horario TEXT
  )`);

  const senhaHash = bcrypt.hashSync("123456", 10);

  db.get(
    "SELECT * FROM usuarios WHERE usuario = ?",
    ["admin"],
    (erro, row) => {
      if (!row) {
        db.run(
          "INSERT INTO usuarios (usuario, senha) VALUES (?, ?)",
          ["admin", senhaHash]
        );
        console.log("Usuário admin criado: senha 123456");
      }
    }
  );
});

// 🔐 MIDDLEWARE TOKEN
function verificarToken(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({
      erro: "Token não fornecido"
    });
  }

  const token = authHeader.split(" ")[1];

  jwt.verify(token, SECRET, (erro, decoded) => {
    if (erro) {
      return res.status(403).json({
        erro: "Token inválido"
      });
    }

    req.user = decoded;
    next();
  });
}

// 🔑 LOGIN
app.post("/login", (req, res) => {
  const { usuario, senha } = req.body;

  if (!usuario || !senha) {
    return res.status(400).json({
      erro: "Usuário e senha são obrigatórios"
    });
  }

  db.get(
    "SELECT * FROM usuarios WHERE usuario = ?",
    [usuario],
    (erro, user) => {
      if (erro) {
        return res.status(500).json({ erro });
      }

      if (!user) {
        return res.status(401).json({
          erro: "Usuário não encontrado"
        });
      }

      const senhaValida = bcrypt.compareSync(senha, user.senha);

      if (!senhaValida) {
        return res.status(401).json({
          erro: "Senha incorreta"
        });
      }

      const token = jwt.sign(
        { id: user.id, usuario: user.usuario },
        SECRET,
        { expiresIn: "1h" }
      );

      res.json({
        mensagem: "Login realizado com sucesso",
        token
      });
    }
  );
});

// 📋 LISTAR (PROTEGIDO)
app.get("/agendamentos", verificarToken, (req, res) => {
  const busca = req.query.busca || "";

  db.all(
    `
    SELECT * FROM agendamentos
    WHERE nome LIKE ?
    ORDER BY horario
    `,
    [`%${busca}%`],
    (erro, rows) => {
      if (erro) {
        return res.status(500).json({ erro });
      }

      res.json(rows);
    }
  );
});

// ➕ CRIAR (PROTEGIDO)
app.post("/agendar", verificarToken, (req, res) => {
  const { nome, horario } = req.body;

  if (!nome || !horario) {
    return res.status(400).json({
      erro: "Nome e horário são obrigatórios"
    });
  }

  db.get(
    "SELECT * FROM agendamentos WHERE horario = ?",
    [horario],
    (erro, agendamentoExistente) => {
      if (erro) {
        return res.status(500).json({ erro });
      }

      if (agendamentoExistente) {
        return res.status(400).json({
          erro: "Esse horário já está ocupado"
        });
      }

      db.run(
        "INSERT INTO agendamentos (nome, horario) VALUES (?, ?)",
        [nome, horario],
        function (erro) {
          if (erro) {
            return res.status(500).json({ erro });
          }

          res.json({
            sucesso: "Agendamento realizado com sucesso",
            id: this.lastID
          });
        }
      );
    }
  );
});

// ❌ REMOVER (PROTEGIDO)
app.delete("/agendamentos/:id", verificarToken, (req, res) => {
  const id = req.params.id;

  db.run(
    "DELETE FROM agendamentos WHERE id = ?",
    [id],
    function (erro) {
      if (erro) {
        return res.status(500).json({ erro });
      }

      res.json({
        mensagem: "Agendamento removido"
      });
    }
  );
});

// ✏️ ATUALIZAR (PROTEGIDO)
app.put("/agendamentos/:id", verificarToken, (req, res) => {
  const id = req.params.id;
  const { nome, horario } = req.body;

  db.get(
    "SELECT * FROM agendamentos WHERE horario = ? AND id != ?",
    [horario, id],
    (erro, agendamentoExistente) => {
      if (erro) {
        return res.status(500).json({ erro });
      }

      if (agendamentoExistente) {
        return res.status(400).json({
          erro: "Esse horário já está ocupado"
        });
      }

      db.run(
        "UPDATE agendamentos SET nome = ?, horario = ? WHERE id = ?",
        [nome, horario, id],
        function (erro) {
          if (erro) {
            return res.status(500).json({ erro });
          }

          res.json({
            sucesso: "Agendamento atualizado com sucesso"
          });
        }
      );
    }
  );
});

// 🚀 SERVIDOR
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log("Servidor rodando");
});