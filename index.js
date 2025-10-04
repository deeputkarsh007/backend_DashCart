const express = require("express");
const cors = require("cors");
require("./db/config");
const User = require("./db/User");
const Product = require("./db/Product");
const Jwt = require("jsonwebtoken");
const jwtKey = "e-comm"; // Secret key

const app = express();
app.use(express.json());
app.use(cors());

// Register endpoint
app.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ message: "Email already registered" });
    }

    const user = new User({ name, email, password });
    let result = await user.save();
    result = result.toObject();
    delete result.password;

    Jwt.sign({ result }, jwtKey, { expiresIn: "2h" }, (err, token) => {
      if (err) {
        res.status(500).send({ result: "Something went wrong" });
      } else {
        res.status(201).send({ result, auth: token });
      }
    });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

// Login endpoint
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res
        .status(400)
        .json({ message: "Email and password are required" });
    }

    const user = await User.findOne({ email, password }).select(
      "-__v -password"
    );

    if (user) {
      Jwt.sign({ user }, jwtKey, { expiresIn: "2h" }, (err, token) => {
        if (err) {
          res.send({ result: "Something went wrong" });
        } else {
          res.send({ user, auth: token });
        }
      });
    } else {
      res.send({ result: "No user found" });
    }
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

// Add product
app.post("/add-product", verifyToken, async (req, res) => {
  try {
    const product = new Product(req.body);
    const result = await product.save();
    res.send(result);
  } catch (error) {
    console.error("Add product error:", error);
    res.status(500).json({ message: "Failed to add product" });
  }
});

// Get all products
app.get("/products", async (req, res) => {
  try {
    const products = await Product.find();
    if (products.length > 0) {
      res.send(products);
    } else {
      res.send({ result: "No products found" });
    }
  } catch (error) {
    console.error("Get products error:", error);
    res.status(500).json({ message: "Failed to fetch products" });
  }
});

// Get product by ID
app.get("/product/:id", async (req, res) => {
  try {
    const result = await Product.findOne({ _id: req.params.id });
    if (result) {
      res.send(result);
    } else {
      res.send({ result: "No Record Found." });
    }
  } catch (error) {
    res.status(400).json({ message: "Invalid product ID" });
  }
});

// Delete product
app.delete("/product/:id", verifyToken, async (req, res) => {
  try {
    const result = await Product.deleteOne({ _id: req.params.id });
    res.send(result);
  } catch (error) {
    res.status(400).json({ message: "Invalid product delete" });
  }
});

// Update product
app.put("/product/:id", verifyToken, async (req, res) => {
  try {
    const result = await Product.updateOne(
      { _id: req.params.id },
      { $set: req.body }
    );
    res.send(result);
  } catch (error) {
    res.status(400).json({ message: "Invalid product update" });
  }
});

// Search products
app.get("/search/:key", verifyToken, async (req, res) => {
  try {
    const result = await Product.find({
      $or: [
        { name: { $regex: req.params.key, $options: "i" } },
        { company: { $regex: req.params.key, $options: "i" } },
        { category: { $regex: req.params.key, $options: "i" } },
      ],
    });
    res.send(result);
  } catch (error) {
    res.status(500).json({ message: "Search failed" });
  }
});

// Get all products by userId (Profile page)
app.get("/user-products/:userId", verifyToken, async (req, res) => {
  try {
    const products = await Product.find({ userId: req.params.userId });
    res.send(products);
  } catch (error) {
    console.error("Error in user-products:", error);
    res.status(500).json({ message: "Failed to fetch user products" });
  }
});

// ✅ Token verification middleware
function verifyToken(req, res, next) {
  let token = req.headers["authorization"];
  if (token) {
    token = token.split(" ")[1];
    Jwt.verify(token, jwtKey, (err, valid) => {
      if (err) {
        res.status(401).send({ result: "Invalid Token" });
      } else {
        next();
      }
    });
  } else {
    res.status(403).send({ result: "Token required" });
  }
}

// ✅ Get logged-in user's profile
app.get("/profile", verifyToken, async (req, res) => {
  try {
    const token = req.headers.authorization.split(" ")[1];
    const decoded = Jwt.verify(token, jwtKey);

    // ✅ Support both token payload formats: from register and login
    const userId = decoded.user?._id || decoded.result?._id;

    if (!userId) {
      return res.status(401).json({ message: "Invalid token payload" });
    }

    const user = await User.findById(userId).select("-password -__v");
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json({ user });
  } catch (error) {
    console.error("Profile fetch error:", error);
    res.status(500).json({ message: "Failed to fetch user profile" });
  }
});

// Start server
app.listen(5002, () => {
  console.log("✅ Server running at http://localhost:5002");
});
