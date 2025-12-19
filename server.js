const express = require("express");
const axios = require("axios");
const jwt = require("jsonwebtoken");

const app = express();

/* ================= CONFIG ================= */

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const JWT_SECRET = process.env.JWT_SECRET || "change_this_secret";

const FRONTEND_URL = "https://bizpilot.biz";
const GOOGLE_REDIRECT_URI =
  "https://bizpilot10.onrender.com/auth/google/callback";

/* ================= START GOOGLE LOGIN ================= */

app.get("/auth/google", (req, res) => {
  const params = new URLSearchParams({
    client_id: GOOGLE_CLIENT_ID,
    redirect_uri: GOOGLE_REDIRECT_URI,
    response_type: "code",
    scope: "openid email profile",
    access_type: "offline",
    prompt: "consent"
  });

  res.redirect(
    "https://accounts.google.com/o/oauth2/v2/auth?" + params.toString()
  );
});

/* ================= GOOGLE CALLBACK ================= */

app.get("/auth/google/callback", async (req, res) => {
  const code = req.query.code;
  if (!code) return res.status(400).send("Missing authorization code");

  try {
    /* Exchange code for Google tokens */
    const tokenResponse = await axios.post(
      "https://oauth2.googleapis.com/token",
      {
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        code: code,
        redirect_uri: GOOGLE_REDIRECT_URI,
        grant_type: "authorization_code"
      },
      { headers: { "Content-Type": "application/json" } }
    );

    const accessToken = tokenResponse.data.access_token;

    /* Get Google user info */
    const userResponse = await axios.get(
      "https://www.googleapis.com/oauth2/v2/userinfo",
      {
        headers: {
          Authorization: `Bearer ${accessToken}`
        }
      }
    );

    const { email, name } = userResponse.data;

    /* Create your own JWT */
    const sessionToken = jwt.sign(
      { email, name },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    /* Redirect back to frontend with token */
    res.redirect(
      `${FRONTEND_URL}/?token=${sessionToken}`
    );

  } catch (err) {
    console.error("Google OAuth error:", err.response?.data || err);
    res.status(500).send("Google authentication failed");
  }
});

/* ================= OPTIONAL: TOKEN CHECK ================= */

app.get("/me", (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: "No token" });

  try {
    const decoded = jwt.verify(auth.split(" ")[1], JWT_SECRET);
    res.json(decoded);
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
});

/* ================= START SERVER ================= */

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("BizPilot backend running on port", PORT);
});
