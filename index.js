require("dotenv").config();
const express = require("express");
const serverless = require("serverless-http");
const cors = require("cors");
const admin = require("firebase-admin");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const Stripe = require("stripe");

const app = express();
const stripe = new Stripe(process.env.PAYMENT_GATEWAY_KEY);

app.use(cors({ origin: "*", credentials: true }));
app.use(express.json());

// === Firebase Admin Init ===
if (!admin.apps.length) {
  const decoded = Buffer.from(process.env.FB_SERVICE_KEY, "base64").toString(
    "utf8"
  );
  const serviceAccount = JSON.parse(decoded);
  admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
}

// === MongoDB Setup ===
const client = new MongoClient(
  `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.0zma47h.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`,
  {
    serverApi: {
      version: ServerApiVersion.v1,
      strict: true,
      deprecationErrors: true,
    },
  }
);

let db,
  usersCol,
  bookingsCol,
  announcementsCol,
  couponsCol,
  membersCol,
  paymentsCol,
  courtsCol;

async function initDB() {
  if (!db) {
    await client.connect();
    db = client.db("sportsClub");
    usersCol = db.collection("users");
    bookingsCol = db.collection("bookings");
    announcementsCol = db.collection("announcements");
    couponsCol = db.collection("coupons");
    membersCol = db.collection("members");
    paymentsCol = db.collection("payments");
    courtsCol = db.collection("courts");
    console.log("MongoDB connected and collections initialized");
  }
}
initDB();

// === Middleware ===
const verifyToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    return res
      .status(401)
      .json({ message: "Unauthorized: Missing Bearer token" });
  }
  try {
    const token = authHeader.split(" ")[1];
    const decoded = await admin.auth().verifyIdToken(token);
    req.decodedUser = decoded;
    next();
  } catch (err) {
    console.error("Token verification error:", err);
    res.status(403).json({ message: "Forbidden: Invalid token" });
  }
};

const verifyAdmin = async (req, res, next) => {
  await initDB();
  const email = req.decodedUser?.email;
  const user = await usersCol.findOne({ email });
  if (!user || user.role !== "admin")
    return res.status(403).json({ message: "Admin access required" });
  next();
};

const verifyMember = async (req, res, next) => {
  await initDB();
  const email = req.decodedUser?.email;
  const user = await usersCol.findOne({ email });
  if (!user || user.role !== "member")
    return res.status(403).json({ message: "Member access required" });
  next();
};

// === USERS Routes ===
app.get("/users/count", verifyToken, verifyAdmin, async (req, res) => {
  await initDB();
  const count = await usersCol.estimatedDocumentCount();
  res.send({ count });
});

app.post("/users", async (req, res) => {
  await initDB();
  const user = req.body;

  if (!user.email)
    return res.status(400).send({ message: "Email is required" });

  const filter = { email: user.email };

  const updateDoc = {
    $set: {
      name: user.name,
      email: user.email,
      role: user.role || "user",
      photo: user.photo,
    },
    $setOnInsert: {
      createdAt: new Date(),
    },
  };

  const result = await usersCol.updateOne(filter, updateDoc, {
    upsert: true,
  });

  res.send(result);
});

app.get("/users", async (req, res) => {
  await initDB();
  const email = req.query.email;
  const query = email ? { email: { $regex: email, $options: "i" } } : {};
  const users = await usersCol.find(query).toArray();
  res.send(users);
});

app.get("/users/search", verifyToken, verifyAdmin, async (req, res) => {
  await initDB();
  const email = req.query.email;
  if (!email) return res.status(400).json({ message: "Email required" });
  const users = await usersCol
    .find({ email: { $regex: new RegExp(email, "i") } })
    .toArray();
  if (!users.length) return res.status(404).json({ message: "No user found." });
  res.send(users);
});

app.get("/users/role/:email", verifyToken, async (req, res) => {
  await initDB();
  const user = await usersCol.findOne({ email: req.params.email });
  res.send({ role: user?.role || "user" });
});

// PATCH role by user ID (admin only)
app.patch("/users/:id/role", verifyToken, verifyAdmin, async (req, res) => {
  await initDB();
  const userId = req.params.id;
  const { role } = req.body;
  const result = await usersCol.updateOne(
    { _id: new ObjectId(userId) },
    { $set: { role } }
  );
  res.send(result);
});

app.get("/users/:email", verifyToken, async (req, res) => {
  await initDB();
  const user = await usersCol.findOne({ email: req.params.email });
  if (!user) return res.status(404).json({ message: "User not found" });
  res.send(user);
});

// === MEMBERS ===
app.post("/members", verifyToken, async (req, res) => {
  await initDB();
  const member = req.body;
  const result = await membersCol.insertOne(member);
  await usersCol.updateOne(
    { email: member.email },
    { $set: { role: "member" } }
  );
  res.send(result);
});

app.get("/members", verifyToken, async (req, res) => {
  await initDB();
  const email = req.query.email;
  if (email) {
    const member = await membersCol.findOne({
      email: { $regex: new RegExp(`^${email}$`, "i") },
    });
    if (!member) return res.status(404).json({ message: "Member not found" });
    return res.send(member);
  }
  const members = await membersCol.find().toArray();
  res.send(members);
});
app.delete("/members/:id", verifyToken, verifyAdmin, async (req, res) => {
  await initDB();
  const memberId = req.params.id;

  try {
    const result = await membersCol.deleteOne({ _id: new ObjectId(memberId) });

    if (result.deletedCount === 0) {
      return res
        .status(404)
        .json({ message: "Member not found or already deleted" });
    }

    // Downgrade user role from member to user (by email)
    const member = await membersCol.findOne({ _id: new ObjectId(memberId) });
    if (member?.email) {
      await usersCol.updateOne(
        { email: member.email },
        { $set: { role: "user" } }
      );
    }

    res.send({ message: "Member deleted successfully", result });
  } catch (error) {
    console.error("Delete member error:", error);
    res
      .status(500)
      .json({ message: "You are not authorized or deletion failed" });
  }
});

app.get("/members/count", verifyToken, verifyAdmin, async (req, res) => {
  await initDB();
  const count = await membersCol.estimatedDocumentCount();
  res.send({ count });
});

// === BOOKINGS ===
app.post("/bookings", verifyToken, async (req, res) => {
  await initDB();
  const booking = { ...req.body, status: req.body.status || "pending" };
  const result = await bookingsCol.insertOne(booking);
  res.send(result);
});

app.get("/bookings", verifyToken, async (req, res) => {
  try {
    await initDB();

    const { status, userEmail, title } = req.query;
    const query = {};

    if (status) {
      query.status = status;
    }

    if (userEmail) {
      query.userEmail = userEmail;
    }

    if (title) {
      query.title = { $regex: new RegExp(title, "i") }; // Case-insensitive match
    }

    const bookings = await bookingsCol.find(query).toArray();
    res.send(bookings);
  } catch (error) {
    console.error("Error fetching bookings:", error);
    res.status(500).send({ error: "Internal Server Error" });
  }
});

app.delete("/bookings/:id", verifyToken, async (req, res) => {
  await initDB();
  const result = await bookingsCol.deleteOne({
    _id: new ObjectId(req.params.id),
  });
  res.send(result);
});

// === KEY PATCH ROUTE ===
app.patch("/bookings/:id", async (req, res) => {
  const id = req.params.id;

  try {
    const booking = await bookingsCol.findOne({ _id: new ObjectId(id) });

    const email = booking.userEmail;
    if (!email) {
      return res.status(400).send({ error: "Email not found in booking" });
    }

    const user = await usersCol.findOne({ email });
    const name = user?.name?.trim() || "Unnamed";

    // insert member
    await membersCol.insertOne({
      email,
      name,
      joinedAt: new Date(),
    });

    // ✅ promote user to member
    await usersCol.updateOne({ email }, { $set: { role: "member" } });

    // update booking status
    await bookingsCol.updateOne(
      { _id: new ObjectId(id) },
      { $set: { status: "approved" } }
    );

    res.send({ message: "Booking approved, member created, user promoted" });
  } catch (err) {
    console.error("Error approving booking:", err);
    res.status(500).send({ error: "Internal server error" });
  }
});

// === COUPONS ===
app.get("/coupons", verifyToken, async (req, res) => {
  await initDB();
  const coupons = await couponsCol.find().toArray();
  res.send(coupons);
});

app.post("/coupons", verifyToken, verifyAdmin, async (req, res) => {
  await initDB();
  const result = await couponsCol.insertOne(req.body);
  res.send(result);
});

app.patch("/coupons/:id", verifyToken, verifyAdmin, async (req, res) => {
  await initDB();
  const result = await couponsCol.updateOne(
    { _id: new ObjectId(req.params.id) },
    { $set: req.body }
  );
  res.send(result);
});

app.delete("/coupons/:id", verifyToken, verifyAdmin, async (req, res) => {
  await initDB();
  const result = await couponsCol.deleteOne({
    _id: new ObjectId(req.params.id),
  });
  res.send(result);
});

// === PAYMENTS ===
app.post("/payments", verifyToken, verifyMember, async (req, res) => {
  await initDB();
  const payment = req.body;
  if (!payment.bookingId)
    return res
      .status(400)
      .json({ message: "bookingId is required in payment data" });
  try {
    const paymentResult = await paymentsCol.insertOne(payment);
    const bookingUpdateResult = await bookingsCol.updateOne(
      { _id: new ObjectId(payment.bookingId) },
      { $set: { status: "confirmed", isPaid: true } }
    );
    if (bookingUpdateResult.modifiedCount === 0)
      return res
        .status(404)
        .json({ message: "Booking not found or already updated" });
    res.send({
      message: "Payment recorded and booking confirmed",
      paymentResult,
      bookingUpdateResult,
    });
  } catch (error) {
    console.error("Payment processing error:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.get("/payments", verifyToken, verifyMember, async (req, res) => {
  await initDB();
  const query = req.query.email ? { email: req.query.email } : {};
  const payments = await paymentsCol.find(query).toArray();
  res.send(payments);
});

app.post(
  "/create-payment-intent",
  verifyToken,
  verifyMember,
  async (req, res) => {
    const { amount } = req.body;
    try {
      const paymentIntent = await stripe.paymentIntents.create({
        amount: Math.round(amount * 100),
        currency: "usd",
        payment_method_types: ["card"],
      });
      res.send({ clientSecret: paymentIntent.client_secret });
    } catch (error) {
      console.error("Stripe error:", error);
      res.status(500).send({ error: "Payment intent creation failed" });
    }
  }
);

app.get(
  "/payments/user/:email",
  verifyToken,
  verifyMember,
  async (req, res) => {
    await initDB();
    const { email } = req.params;
    const payments = await paymentsCol
      .find({ email })
      .sort({ paidAt: -1 })
      .toArray();
    res.send(payments);
  }
);

// === ANNOUNCEMENTS ===
app.get("/announcements", verifyToken, async (req, res) => {
  await initDB();
  const announcements = await announcementsCol.find().toArray();
  res.send(announcements);
});

app.post("/announcements", verifyToken, verifyAdmin, async (req, res) => {
  await initDB();
  const result = await announcementsCol.insertOne(req.body);
  res.send(result);
});
app.patch("/announcements/:id", verifyToken, verifyAdmin, async (req, res) => {
  await initDB();
  const announcementId = req.params.id;
  const updateData = req.body;

  try {
    const result = await announcementsCol.updateOne(
      { _id: new ObjectId(announcementId) },
      { $set: updateData }
    );

    if (result.modifiedCount === 0) {
      return res
        .status(404)
        .json({ message: "Announcement not found or no changes made" });
    }

    res.send({ message: "Announcement updated successfully", result });
  } catch (error) {
    console.error("Announcement update error:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.delete("/announcements/:id", verifyToken, verifyAdmin, async (req, res) => {
  await initDB();
  const result = await announcementsCol.deleteOne({
    _id: new ObjectId(req.params.id),
  });
  res.send(result);
});

app.get("/courts", async (req, res) => {
  await initDB();
  const courts = await courtsCol.find().toArray();
  res.send(courts);
});

app.post("/courts", verifyToken, verifyAdmin, async (req, res) => {
  await initDB();
  const result = await courtsCol.insertOne(req.body);
  res.send(result);
});

app.delete("/courts/:id", verifyToken, verifyAdmin, async (req, res) => {
  await initDB();
  const result = await courtsCol.deleteOne({
    _id: new ObjectId(req.params.id),
  });
  res.send(result);
});

app.get("/courts/count", verifyToken, verifyAdmin, async (req, res) => {
  await initDB();
  const count = await courtsCol.estimatedDocumentCount();
  res.send({ count });
});

app.get("/", (req, res) => {
  res.send({ message: "Vercel server running without /api prefix" });
});

app.get("/test", (req, res) => {
  res.json({ message: "Hello from backend" });
});

module.exports = app;
module.exports.handler = serverless(app);
