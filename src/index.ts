import axios from "axios";
import fastify, { FastifyRequest } from "fastify";
import fastifyCookie from "fastify-cookie";
import { callback, client, domain, Oauth2, secret } from "./config";

const app = fastify({ logger: true });

app.register(fastifyCookie, {
  secret,
  parseOptions: {
    secure: true,
    httpOnly: false,
    maxAge: 6048e5,
  },
});

app.get("/login", async (req, reply) => {
  if (isAuthenticated(req)) return await reply.redirect(200, `${domain}/info`);

  return await reply.redirect(Oauth2);
});

app.get("/logout", async (req, res) => {
  if (!isAuthenticated(req))
    return await res.status(401).send({ message: "Not Authorized" });
  await res.clearCookie("token");
  return await res.redirect(`${domain}/login`);
});

app.get("/callback", async (req, reply) => {
  const { code } = req.query as any;

  if (!code)
    return await reply.status(404).send({ message: "No code provided." });

  try {
    const data = await axios.post(
      "https://discord.com/api/v10/oauth2/token",
      new URLSearchParams({
        client_id: client.id,
        client_secret: client.secret,
        grant_type: "authorization_code",
        code,
        redirect_uri: callback,
      }),
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
      }
    );

    await reply.setCookie("token", data.data.access_token);
    return await reply.status(200).redirect(`${domain}/info`);
  } catch (e) {
    console.error(e);
    return await reply.status(404).send({ message: "An error has occoured" });
  }
});

app.get("/info", async (req, res) => {
  if (!isAuthenticated(req))
    return await res.status(401).send({ message: "Not Authorized" });

  const data = await axios.get("https://discord.com/api/v10/users/@me", {
    headers: { Authorization: `Bearer ${req.cookies.token}` },
  });

  return res.status(200).send(data.data);
});

function isAuthenticated(req: FastifyRequest) {
  return req.cookies.token ? true : false;
}

app.listen(9012);
