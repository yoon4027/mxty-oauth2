import axios from "axios";
import fastify, { FastifyReply, FastifyRequest } from "fastify";
import fastifyCookie from "fastify-cookie";
import { callback, client, Oauth2, secret } from "./config";

const app = fastify({ logger: true });
const apiURL = `https://canary.discord.com/api/v10`;

app.register(fastifyCookie, {
  secret,
  parseOptions: {
    secure: true,
    httpOnly: false,
    maxAge: 604800,
  },
});

app.setNotFoundHandler(async (req, reply) => {
  if (!isAuthenticated(req)) return await reply.status(302).redirect("/login");
  return await reply.status(302).redirect("/info");
});

app.get("/login", async (req, reply) => {
  if (isAuthenticated(req)) return await reply.redirect(`/info`);
  return await reply.redirect(Oauth2);
});

app.get("/logout", async (req, res) => {
  if (!isAuthenticated(req))
    return await res.status(401).send({ message: "Not Authorized" });

  await axios
    .post(
      `${apiURL}/oauth2/token/revoke`,
      new URLSearchParams({
        client_id: client.id,
        client_secret: client.secret,
        token: req.cookies.token,
      })
    )
    .catch(() => null);

  res.clearCookie("token");
  return await res.redirect(`/login`);
});

app.get(
  "/callback",
  { schema: { querystring: { code: { type: "string" } } } },
  async (req, reply) => {
    const code = (req.query as any).code as string;

    if (!code)
      return await reply.status(404).send({ message: "No code provided." });

    try {
      const data = await axios.post(
        `${apiURL}/oauth2/token`,
        new URLSearchParams({
          client_id: client.id,
          client_secret: client.secret,
          grant_type: "authorization_code",
          code: code.toString(),
          redirect_uri: callback,
        }),
        {
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
          },
        }
      );

      reply.setCookie("token", data.data.access_token);
      reply.setCookie("refreshToken", data.data.refresh_token);
      return reply.redirect(`/info`);
    } catch (e) {
      console.error(e);
      return await reply.status(404).send({ message: "An error has occoured" });
    }
  }
);

app.get("/info", async (req, reply) => {
  if (!isAuthenticated(req))
    return await reply.status(401).send({ message: "Not Authorized" });

  const data = await fetchUserData(req.cookies.token);

  if (!data) {
    const data = await refreshToken(req, reply);

    return reply.status(200).send(await fetchUserData(data.access_token));
  }

  await refreshToken(req, reply);
  return reply.status(200).send(data!.data);
});

function isAuthenticated(req: FastifyRequest): boolean {
  return Boolean(req.cookies.token);
}

async function fetchUserData(accessToken: string) {
  return await axios
    .get(`${apiURL}/users/@me`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    })
    .catch(() => null);
}

async function refreshToken(req: FastifyRequest, reply: FastifyReply) {
  const data = await axios
    .post(
      `${apiURL}/oauth2/token`,
      new URLSearchParams({
        client_id: client.id,
        client_secret: client.secret,
        grant_type: "refresh_token",
        refresh_token: req.cookies.refreshToken,
      })
    )
    .catch(() => null);

  if (!data) return null;

  const { data: newData } = data;

  reply.setCookie("token", newData.access_token);
  reply.setCookie("refreshToken", newData.refresh_token);

  return newData;
}

app.listen(9012);
