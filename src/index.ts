import axios from "axios";
import express from "express";
import session from "express-session";
import { domain } from "./config";

const secret = "verySecret";

const app = express();
app.use(
  session({
    secret,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: "auto",
      sameSite: false,
      httpOnly: false,
      maxAge: 6048e5,
    },
  })
);

app.get("/login", async (_, reply) => {
  return reply.redirect(
    "https://discord.com/api/oauth2/authorize?client_id=965211726817660978&redirect_uri=http%3A%2F%2Flocalhost%3A9012%2Fcallback&response_type=code&scope=identify"
  );
});

app.get("/logout", async (req, res) => {
  if (!(req.session as any).token)
    return res.status(401).send({ message: "Not Authorized" });
  req.session.destroy(() => null);
  return res.redirect(`${domain}/login`);
});

app.get("/callback", async (req, reply) => {
  const { code } = req.query as any;

  try {
    const data = await axios.post(
      "https://discord.com/api/v10/oauth2/token",
      new URLSearchParams({
        client_id: "965211726817660978",
        client_secret: "kGQQNKRNvGwMcLzEj19Pe-rxL9ulHG7L",
        grant_type: "authorization_code",
        code,
        redirect_uri: "http://localhost:9012/callback",
      }),
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
      }
    );

    (req.session as any).token = data.data.access_token;
    return reply.status(200).redirect("${domain}/info");
  } catch (e) {
    reply.status(404);
    console.error(e);
  }
});

app.get("/info", async (req, res) => {
  const token = (req.session as any).token as string;

  if (!token) return res.status(401).send({ message: "Not Authorized" });

  const data = await axios.get("https://discord.com/api/v10/users/@me", {
    headers: { Authorization: `Bearer ${token}` },
  });

  return res.status(200).send(data.data);
});

app.listen(9012);
