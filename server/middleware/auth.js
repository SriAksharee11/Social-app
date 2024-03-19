import jwt from "jsonwebtoken";

export const verifyToken = async (req, res, next) => {
  try {
    let token = req.header("Authorization");

    if (!token) {
      return res.status(403).send("Access Denied: No token provided");
    }

    if (token.startsWith("Bearer ")) {
      token = token.slice(7, token.length).trimLeft();
    }

    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified;
    next();
  } catch (err) {
    if (err.name === "JsonWebTokenError") {
      return res.status(401).send("Invalid token");
    }
    if (err.name === "TokenExpiredError") {
      return res.status(401).send("Token expired");
    }
    res.status(500).json({ error: "Internal Server Error" });
  }
};
