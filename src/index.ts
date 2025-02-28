import path from "node:path";
import { fileURLToPath } from "node:url";
import SQLiteStoreFactory from "connect-sqlite3";
import express from "express";
import session from "express-session";
import multer from "multer";
import cron from "node-cron";
import {
  compareFiles,
  getAllUsers,
  getAnalyticsData,
  getFileById,
  getFileMatches,
  getPendingCreditRequests,
  getUserByEmail,
  getUserById,
  getUserCreditRequests,
  getUserFiles,
  isAdmin,
  isAuthenticated,
  processCreditRequest,
  processUploadedFile,
  registerUser,
  requestCredits,
  updateUserCredits,
  updateUserRole,
} from "./services";
import { comparePassword, hashPassword, initDb } from "./utils";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const upload = multer({ dest: "temp/" });

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

const SQLiteStore = SQLiteStoreFactory(session) as unknown as {
  new (options?: any): session.Store;
};
app.use(
  session({
    store: new SQLiteStore({ db: "sessions.sqlite", dir: "./" }),
    secret: "e334aa515718d7613f52646f0e92a7ff8bd2b2b81bbde28d27698c4a1e9d8fc8",
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false },
  })
);

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

cron.schedule("0 0 * * *", async () => {
  const db = await initDb();
  await db.run("UPDATE users SET credits = 20");
  await db.close();
});

app.get("/auth/login", (req, res) =>
  res.render("login", { message: null, title: "Login" })
);

app.get("/auth/signup", (req, res) =>
  res.render("signup", { message: null, title: "Sign Up" })
);

app.post("/auth/signup", async (req, res) => {
  const { firstname, lastname, email, password, confirmPassword } = req.body;
  if (password !== confirmPassword)
    return res.render("signup", {
      message: "Passwords do not match",
      title: "Sign Up",
    });

  try {
    const hashedPassword = await hashPassword(password);
    await registerUser(firstname, lastname, email, hashedPassword);
    res.redirect("/auth/login");
  } catch (error) {
    console.warn(error);
    res.render("signup", {
      message: "An error occurred. Email might already be registered.",
      title: "Sign Up",
    });
  }
});

app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await getUserByEmail(email);
    if (user && (await comparePassword(password, user.password))) {
      req.session.user = {
        id: user.id,
        email: user.email,
        firstname: user.firstname,
        lastname: user.lastname,
        role: user.role,
        credits: user.credits,
      };
      res.redirect("/");
    } else {
      res.render("login", {
        message: "Invalid email or password",
        title: "Login",
      });
    }
  } catch (error) {
    console.warn(error);
    res.render("login", {
      message:
        "An error occurred while processing your request. Please try again.",
      title: "Login",
    });
  }
});

app.get("/auth/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error(err);
      res.status(500).send("Error logging out.");
    } else {
      res.redirect("/");
    }
  });
});

app.get("/", isAuthenticated, async (req, res) => {
  try {
    if (req.session.user) {
      const userInfo = await getUserById(req.session.user.id);
      if (userInfo) {
        req.session.user.credits = userInfo.credits;
      }
    }

    res.render("dashboard", {
      user: req.session.user,
    });
  } catch (error) {
    console.error(error);
    res.status(500).send("Error loading dashboard");
  }
});

app.get("/scans", isAuthenticated, async (req, res) => {
  try {
    const userId = req.session.user?.id;
    const userFiles = await getUserFiles(userId!);
    res.json(userFiles);
  } catch (error) {
    console.error(error);
    res.status(500).send("Error loading scans");
  }
});

app.get("/scans/:id", isAuthenticated, async (req, res) => {
  const fileId = Number.parseInt(req.params.id);

  try {
    const file = await getFileById(fileId);
    if (!file) {
      res.status(404).send("File not found");
      return;
    }

    const matches = await getFileMatches(fileId);
    res.render("scan", { user: req.session.user, file, matches });
  } catch (error) {
    console.error(error);
    res.status(500).send("Error loading scan details");
  }
});

app.post(
  "/upload",
  isAuthenticated,
  upload.single("file"),
  async (req, res) => {
    try {
      if (req.session.user?.id === undefined) {
        res.status(400).json({ error: "User not found" });
        return;
      }

      const result = await processUploadedFile(req.file!, req.session.user?.id);
      res
        .status(200)
        .json({
          message: "File uploaded and text saved successfully.",
          fileId: result.fileId,
        });
    } catch (error: any) {
      console.error(error);
      res
        .status(400)
        .json({ error: error.message || "Error processing file." });
    }
  }
);

app.post("/compare/:id", isAuthenticated, async (req, res) => {
  const id = Number.parseInt(req.params.id);

  try {
    const result = await compareFiles(id);
    res.status(200).json({
      message: "Comparison complete",
      bestMatch: result.bestMatch,
    });
  } catch (error: any) {
    console.error(error);
    res
      .status(500)
      .json({ error: error.message || "Error processing document comparison" });
  }
});

app.get("/credits/history", isAuthenticated, async (req, res) => {
  try {
    const userId = req.session.user?.id;
    const creditRequests = await getUserCreditRequests(userId!);
    res.json(creditRequests);
  } catch (error) {
    console.error(error);
    res.status(500).send("Error loading credit history");
  }
});

app.post("/credits/request", isAuthenticated, async (req, res) => {
  const { creditsRequested, reason } = req.body;
  const userId = req.session.user?.id;

  if (!userId || !creditsRequested || !reason) {
    res.status(400).json({ error: "Missing required fields" });
    return;
  }

  try {
    await requestCredits(userId, creditsRequested, reason);
    res.status(200).json({ message: "Credit request submitted successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error submitting credit request" });
  }
});

app.get(
  "/admin/credit-requests",
  isAuthenticated,
  isAdmin,
  async (req, res) => {
    try {
      const requests = await getPendingCreditRequests();
      res.render("credit-requests", {
        user: req.session.user,
        requests,
      });
    } catch (error) {
      console.error(error);
      res.status(500).send("Error loading credit requests");
    }
  }
);

app.post(
  "/admin/credit-requests/:id",
  isAuthenticated,
  isAdmin,
  async (req, res) => {
    const id = Number.parseInt(req.params.id);
    const { action } = req.body;
    const adminId = req.session.user?.id;

    if (!["approve", "deny"].includes(action)) {
      res.status(400).json({ error: "Invalid action" });
      return;
    }

    try {
      await processCreditRequest(id, adminId!, action);
      res
        .status(200)
        .json({
          message: `Request ${
            action === "approve" ? "approved" : "denied"
          } successfully`,
        });
    } catch (error: any) {
      console.error(error);
      res
        .status(500)
        .json({
          error:
            error.message ||
            `Error ${action === "approve" ? "approving" : "denying"} request`,
        });
    }
  }
);

app.get(
  "/admin/user-management",
  isAuthenticated,
  isAdmin,
  async (req, res) => {
    try {
      const users = await getAllUsers();
      res.render("admin-dashboard", {
        user: req.session.user,
        users,
      });
    } catch (error) {
      console.error(error);
      res.status(500).send("Error loading users");
    }
  }
);

app.post(
  "/admin/user/:id/credits",
  isAuthenticated,
  isAdmin,
  async (req, res) => {
    const id = Number.parseInt(req.params.id);
    const { credits } = req.body;

    if (!credits) {
      res.status(400).json({ error: "Credits amount is required" });
      return;
    }

    try {
      await updateUserCredits(id, credits);
      res.status(200).json({ message: "Credits updated successfully" });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: "Error updating credits" });
    }
  }
);

app.post("/admin/user/:id/role", isAuthenticated, isAdmin, async (req, res) => {
  const id = Number.parseInt(req.params.id);
  const { role } = req.body;

  if (!role || !["user", "admin"].includes(role)) {
    res.status(400).json({ error: "Valid role is required" });
    return;
  }

  try {
    await updateUserRole(id, role);
    res.status(200).json({ message: "Role updated successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error updating role" });
  }
});

app.get("/admin/analytics", isAuthenticated, isAdmin, async (req, res) => {
  try {
    const { topUsers, dailyStats, creditStats } = await getAnalyticsData();

    res.render("admin-analytics", {
      user: req.session.user,
      topUsers,
      dailyStats,
      creditStats,
    });
  } catch (error) {
    console.error(error);
    res.status(500).send("Error loading analytics");
  }
});

app.listen(3000, () =>
  console.warn("Server is running on http://localhost:3000")
);

export default app;
