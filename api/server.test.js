const request = require("supertest");
const server = require("../api/server");
const db = require("../data/dbConfig");

beforeAll(async () => {
  await db.migrate.rollback();
  await db.migrate.latest();
});

beforeEach(async () => {
  await db("users").truncate();
});

afterAll(async () => {
  await db.destroy();
});

describe("Auth Endpoints", () => {
  const user = { username: "CaptainMarvel", password: "foobar" };

  describe("[POST] /api/auth/register", () => {
    it("registers a new user", async () => {
      const res = await request(server).post("/api/auth/register").send(user);
      expect(res.status).toBe(201);
      expect(res.body.username).toBe("CaptainMarvel");
      expect(res.body).toHaveProperty("password");
    });

    it("fails to register without username or password", async () => {
      const res = await request(server)
        .post("/api/auth/register")
        .send({ username: "MissingPassword" });

      expect(res.status).toBe(400);
      expect(res.body.message).toBe("username and password required");
    });

    it("fails to register with existing username", async () => {
      await request(server).post("/api/auth/register").send(user);
      const res = await request(server).post("/api/auth/register").send(user);

      expect(res.status).toBe(400);
      expect(res.body.message).toBe("username taken");
    });
  });

  describe("[POST] /api/auth/login", () => {
    beforeEach(async () => {
      await request(server).post("/api/auth/register").send(user);
    });

    it("logs in a registered user and returns a token", async () => {
      const res = await request(server).post("/api/auth/login").send(user);
      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty("token");
      expect(res.body.message).toBe("welcome, CaptainMarvel");
    });

    it("fails to log in with incorrect credentials", async () => {
      const res = await request(server)
        .post("/api/auth/login")
        .send({ username: "CaptainMarvel", password: "wrongpass" });

      expect(res.status).toBe(401);
      expect(res.body.message).toBe("invalid credentials");
    });

    it("fails to log in without username or password", async () => {
      const res = await request(server)
        .post("/api/auth/login")
        .send({ username: "CaptainMarvel" });

      expect(res.status).toBe(400);
      expect(res.body.message).toBe("username and password required");
    });
  });

  describe("[GET] /api/jokes (Protected Route)", () => {
    let token;

    beforeEach(async () => {
      await request(server).post("/api/auth/register").send(user);
      const loginRes = await request(server).post("/api/auth/login").send(user);
      token = loginRes.body.token;
    });

    it("denies access without a token", async () => {
      const res = await request(server).get("/api/jokes");
      expect(res.status).toBe(401);
      expect(res.body.message).toBe("token required");
    });

    it("allows access with a valid token", async () => {
      const res = await request(server)
        .get("/api/jokes")
        .set("Authorization", token);
      expect(res.status).toBe(200);
      expect(res.body.length).toBeGreaterThan(0);
    });
  });
});