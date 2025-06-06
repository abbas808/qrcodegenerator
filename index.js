var __defProp = Object.defineProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// server/index.ts
import express2 from "express";

// server/routes.ts
import { createServer } from "http";

// db/index.ts
import { Pool, neonConfig } from "@neondatabase/serverless";
import { drizzle } from "drizzle-orm/neon-serverless";
import ws from "ws";

// shared/schema.ts
var schema_exports = {};
__export(schema_exports, {
  barcodes: () => barcodes,
  barcodesRelations: () => barcodesRelations,
  batchItems: () => batchItems,
  batchItemsRelations: () => batchItemsRelations,
  batchJobs: () => batchJobs,
  batchJobsRelations: () => batchJobsRelations,
  insertBarcodeSchema: () => insertBarcodeSchema,
  insertBatchItemSchema: () => insertBatchItemSchema,
  insertBatchJobSchema: () => insertBatchJobSchema,
  insertPaymentSchema: () => insertPaymentSchema,
  insertQrCodeSchema: () => insertQrCodeSchema,
  insertScannedCodeSchema: () => insertScannedCodeSchema,
  insertSubscriptionPlanSchema: () => insertSubscriptionPlanSchema,
  insertUserSchema: () => insertUserSchema,
  insertUserSubscriptionSchema: () => insertUserSubscriptionSchema,
  loginSchema: () => loginSchema,
  payments: () => payments,
  paymentsRelations: () => paymentsRelations,
  qrCodes: () => qrCodes,
  qrCodesRelations: () => qrCodesRelations,
  resetPasswordSchema: () => resetPasswordSchema,
  scannedCodes: () => scannedCodes,
  scannedCodesRelations: () => scannedCodesRelations,
  sessions: () => sessions,
  subscriptionPlans: () => subscriptionPlans,
  subscriptionPlansRelations: () => subscriptionPlansRelations,
  userSubscriptions: () => userSubscriptions,
  userSubscriptionsRelations: () => userSubscriptionsRelations,
  users: () => users,
  usersRelations: () => usersRelations
});
import { pgTable, text, serial, integer, boolean, timestamp, jsonb, varchar, decimal, index } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";
import { relations } from "drizzle-orm";
var sessions = pgTable(
  "sessions",
  {
    sid: varchar("sid").primaryKey(),
    sess: jsonb("sess").notNull(),
    expire: timestamp("expire").notNull()
  },
  (table) => [index("IDX_session_expire").on(table.expire)]
);
var users = pgTable("users", {
  id: varchar("id").primaryKey().notNull(),
  email: text("email").unique(),
  firstName: text("first_name"),
  lastName: text("last_name"),
  profileImageUrl: text("profile_image_url"),
  isActive: boolean("is_active").default(true).notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
  lastLoginAt: timestamp("last_login_at")
});
var subscriptionPlans = pgTable("subscription_plans", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  description: text("description").notNull(),
  price: decimal("price", { precision: 10, scale: 2 }).notNull(),
  currency: text("currency").notNull().default("INR"),
  durationDays: integer("duration_days").notNull(),
  features: jsonb("features"),
  isActive: boolean("is_active").default(true).notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull()
});
var userSubscriptions = pgTable("user_subscriptions", {
  id: serial("id").primaryKey(),
  userId: varchar("user_id").references(() => users.id).notNull(),
  planId: integer("plan_id").references(() => subscriptionPlans.id).notNull(),
  startDate: timestamp("start_date").defaultNow().notNull(),
  endDate: timestamp("end_date").notNull(),
  isActive: boolean("is_active").default(true).notNull(),
  autoRenew: boolean("auto_renew").default(false).notNull(),
  cancelledAt: timestamp("cancelled_at"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull()
});
var payments = pgTable("payments", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").references(() => users.id).notNull(),
  subscriptionId: integer("subscription_id").references(() => userSubscriptions.id),
  razorpayPaymentId: text("razorpay_payment_id").unique(),
  razorpayOrderId: text("razorpay_order_id").unique(),
  razorpaySignature: text("razorpay_signature"),
  amount: decimal("amount", { precision: 10, scale: 2 }).notNull(),
  currency: text("currency").notNull().default("INR"),
  status: text("status").notNull().default("created"),
  // created, authorized, captured, refunded, failed
  paymentMethod: text("payment_method"),
  paymentData: jsonb("payment_data"),
  // Store additional payment details
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull()
});
var qrCodes = pgTable("qr_codes", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").references(() => users.id),
  name: text("name").notNull(),
  content: text("content").notNull(),
  type: text("type").notNull().default("URL"),
  // URL, TEXT, EMAIL, etc.
  settings: jsonb("settings").notNull(),
  // Store color, size, pattern, etc.
  dataUrl: text("data_url"),
  // Store the generated data URL
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull()
});
var barcodes = pgTable("barcodes", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").references(() => users.id),
  name: text("name").notNull(),
  content: text("content").notNull(),
  format: text("format").notNull().default("CODE128"),
  // CODE128, EAN13, etc.
  settings: jsonb("settings").notNull(),
  // Store color, width, height, etc.
  dataUrl: text("data_url"),
  // Store the generated data URL
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull()
});
var scannedCodes = pgTable("scanned_codes", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").references(() => users.id),
  content: text("content").notNull(),
  format: text("format").notNull(),
  // QR_CODE, EAN13, etc.
  scannedAt: timestamp("scanned_at").defaultNow().notNull()
});
var batchJobs = pgTable("batch_jobs", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").references(() => users.id),
  name: text("name").notNull(),
  status: text("status").notNull().default("pending"),
  // pending, processing, completed, failed
  itemCount: integer("item_count").notNull(),
  completedCount: integer("completed_count").notNull().default(0),
  settings: jsonb("settings").notNull(),
  // Common settings for all items
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull()
});
var batchItems = pgTable("batch_items", {
  id: serial("id").primaryKey(),
  batchJobId: integer("batch_job_id").references(() => batchJobs.id).notNull(),
  content: text("content").notNull(),
  status: text("status").notNull().default("pending"),
  // pending, completed, failed
  dataUrl: text("data_url"),
  // Store the generated data URL
  error: text("error")
  // Store error message if failed
});
var usersRelations = relations(users, ({ many }) => ({
  qrCodes: many(qrCodes),
  barcodes: many(barcodes),
  scannedCodes: many(scannedCodes),
  batchJobs: many(batchJobs),
  subscriptions: many(userSubscriptions),
  payments: many(payments)
}));
var subscriptionPlansRelations = relations(subscriptionPlans, ({ many }) => ({
  userSubscriptions: many(userSubscriptions)
}));
var userSubscriptionsRelations = relations(userSubscriptions, ({ one, many }) => ({
  user: one(users, { fields: [userSubscriptions.userId], references: [users.id] }),
  plan: one(subscriptionPlans, { fields: [userSubscriptions.planId], references: [subscriptionPlans.id] }),
  payments: many(payments)
}));
var paymentsRelations = relations(payments, ({ one }) => ({
  user: one(users, { fields: [payments.userId], references: [users.id] }),
  subscription: one(userSubscriptions, {
    fields: [payments.subscriptionId],
    references: [userSubscriptions.id]
  })
}));
var qrCodesRelations = relations(qrCodes, ({ one }) => ({
  user: one(users, { fields: [qrCodes.userId], references: [users.id] })
}));
var barcodesRelations = relations(barcodes, ({ one }) => ({
  user: one(users, { fields: [barcodes.userId], references: [users.id] })
}));
var scannedCodesRelations = relations(scannedCodes, ({ one }) => ({
  user: one(users, { fields: [scannedCodes.userId], references: [users.id] })
}));
var batchJobsRelations = relations(batchJobs, ({ one, many }) => ({
  user: one(users, { fields: [batchJobs.userId], references: [users.id] }),
  items: many(batchItems)
}));
var batchItemsRelations = relations(batchItems, ({ one }) => ({
  job: one(batchJobs, { fields: [batchItems.batchJobId], references: [batchJobs.id] })
}));
var insertUserSchema = createInsertSchema(users, {
  username: (schema) => schema.min(3, "Username must be at least 3 characters"),
  password: (schema) => schema.min(6, "Password must be at least 6 characters"),
  email: (schema) => schema.email("Please enter a valid email")
});
var loginSchema = z.object({
  username: z.string().min(3, "Username must be at least 3 characters"),
  password: z.string().min(6, "Password must be at least 6 characters")
});
var resetPasswordSchema = z.object({
  token: z.string(),
  password: z.string().min(6, "Password must be at least 6 characters"),
  confirmPassword: z.string().min(6, "Password must be at least 6 characters")
}).refine((data) => data.password === data.confirmPassword, {
  message: "Passwords do not match",
  path: ["confirmPassword"]
});
var insertSubscriptionPlanSchema = createInsertSchema(subscriptionPlans, {
  name: (schema) => schema.min(2, "Plan name must be at least 2 characters"),
  price: (schema) => schema.refine((val) => Number(val) > 0, "Price must be positive"),
  durationDays: (schema) => schema.refine((val) => Number(val) > 0, "Duration must be positive")
});
var insertUserSubscriptionSchema = createInsertSchema(userSubscriptions);
var insertPaymentSchema = createInsertSchema(payments);
var insertQrCodeSchema = createInsertSchema(qrCodes);
var insertBarcodeSchema = createInsertSchema(barcodes);
var insertScannedCodeSchema = createInsertSchema(scannedCodes);
var insertBatchJobSchema = createInsertSchema(batchJobs);
var insertBatchItemSchema = createInsertSchema(batchItems);

// db/index.ts
neonConfig.webSocketConstructor = ws;
if (!process.env.DATABASE_URL) {
  throw new Error(
    "DATABASE_URL must be set. Did you forget to provision a database?"
  );
}
var pool = new Pool({ connectionString: process.env.DATABASE_URL });
var db = drizzle({ client: pool, schema: schema_exports });

// server/storage.ts
import { and, eq } from "drizzle-orm";
var Storage = class {
  // User methods for Replit Auth
  async getUser(id) {
    const [user] = await db.select().from(users).where(eq(users.id, id));
    return user;
  }
  async upsertUser(userData) {
    const [user] = await db.insert(users).values(userData).onConflictDoUpdate({
      target: users.id,
      set: {
        ...userData,
        updatedAt: /* @__PURE__ */ new Date()
      }
    }).returning();
    return user;
  }
  // Legacy user methods
  async getUserByUsername(username) {
    const result = await db.select().from(users).where(eq(users.username, username));
    return result[0];
  }
  async insertUser(user) {
    const result = await db.insert(users).values(user).returning();
    return result[0];
  }
  // QR Code methods
  async getQrCodesByUserId(userId) {
    return await db.select().from(qrCodes).where(eq(qrCodes.userId, userId));
  }
  async getQrCodeById(id, userId) {
    const query = userId ? and(eq(qrCodes.id, id), eq(qrCodes.userId, userId)) : eq(qrCodes.id, id);
    const result = await db.select().from(qrCodes).where(query);
    return result[0];
  }
  async insertQrCode(qrCode) {
    const result = await db.insert(qrCodes).values(qrCode).returning();
    return result[0];
  }
  async updateQrCode(id, userId, data) {
    const result = await db.update(qrCodes).set({ ...data, updatedAt: /* @__PURE__ */ new Date() }).where(and(eq(qrCodes.id, id), eq(qrCodes.userId, userId))).returning();
    return result[0];
  }
  async deleteQrCode(id, userId) {
    const result = await db.delete(qrCodes).where(and(eq(qrCodes.id, id), eq(qrCodes.userId, userId))).returning();
    return result.length > 0;
  }
  // Barcode methods
  async getBarcodesByUserId(userId) {
    return await db.select().from(barcodes).where(eq(barcodes.userId, userId));
  }
  async getBarcodeById(id, userId) {
    const query = userId ? and(eq(barcodes.id, id), eq(barcodes.userId, userId)) : eq(barcodes.id, id);
    const result = await db.select().from(barcodes).where(query);
    return result[0];
  }
  async insertBarcode(barcode) {
    const result = await db.insert(barcodes).values(barcode).returning();
    return result[0];
  }
  async updateBarcode(id, userId, data) {
    const result = await db.update(barcodes).set({ ...data, updatedAt: /* @__PURE__ */ new Date() }).where(and(eq(barcodes.id, id), eq(barcodes.userId, userId))).returning();
    return result[0];
  }
  async deleteBarcode(id, userId) {
    const result = await db.delete(barcodes).where(and(eq(barcodes.id, id), eq(barcodes.userId, userId))).returning();
    return result.length > 0;
  }
  // Scanned code methods
  async getScannedCodesByUserId(userId, limit = 20) {
    return await db.select().from(scannedCodes).where(eq(scannedCodes.userId, userId)).orderBy(scannedCodes.scannedAt).limit(limit);
  }
  async insertScannedCode(code) {
    const result = await db.insert(scannedCodes).values(code).returning();
    return result[0];
  }
  // Batch job methods
  async getBatchJobsByUserId(userId) {
    return await db.select().from(batchJobs).where(eq(batchJobs.userId, userId)).orderBy(batchJobs.createdAt);
  }
  async getBatchJobById(id, userId) {
    const query = userId ? and(eq(batchJobs.id, id), eq(batchJobs.userId, userId)) : eq(batchJobs.id, id);
    const result = await db.select().from(batchJobs).where(query);
    return result[0];
  }
  async insertBatchJob(job) {
    const result = await db.insert(batchJobs).values(job).returning();
    return result[0];
  }
  async updateBatchJob(id, userId, data) {
    const result = await db.update(batchJobs).set({ ...data, updatedAt: /* @__PURE__ */ new Date() }).where(and(eq(batchJobs.id, id), eq(batchJobs.userId, userId))).returning();
    return result[0];
  }
  // Batch items methods
  async getBatchItemsByJobId(jobId) {
    return await db.select().from(batchItems).where(eq(batchItems.batchJobId, jobId));
  }
  async insertBatchItem(item) {
    const result = await db.insert(batchItems).values(item).returning();
    return result[0];
  }
  async updateBatchItem(id, data) {
    const result = await db.update(batchItems).set(data).where(eq(batchItems.id, id)).returning();
    return result[0];
  }
  async insertBatchItems(items) {
    if (items.length === 0) return [];
    const result = await db.insert(batchItems).values(items).returning();
    return result;
  }
};
var storage = new Storage();

// server/routes.ts
import multer from "multer";
import { eq as eq4 } from "drizzle-orm";

// server/auth.ts
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { eq as eq2 } from "drizzle-orm";
var JWT_SECRET = process.env.JWT_SECRET || "qr-code-generator-secret-key";
var TOKEN_EXPIRY = "7d";
var generateToken = (user) => {
  const payload = {
    id: user.id,
    username: user.username,
    email: user.email
  };
  return jwt.sign(payload, JWT_SECRET, { expiresIn: TOKEN_EXPIRY });
};
var verifyPassword = async (password, hashedPassword) => {
  return await bcrypt.compare(password, hashedPassword);
};
var hashPassword = async (password) => {
  const salt = await bcrypt.genSalt(10);
  return await bcrypt.hash(password, salt);
};
var authenticateJWT = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return res.status(401).json({ message: "No authentication token provided" });
    }
    const token = authHeader.split(" ")[1];
    if (!token) {
      return res.status(401).json({ message: "Invalid token format" });
    }
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await db.query.users.findFirst({
      where: eq2(users.id, decoded.id)
    });
    if (!user) {
      return res.status(401).json({ message: "User not found" });
    }
    req.user = user;
    next();
  } catch (error) {
    console.error("Authentication error:", error);
    return res.status(401).json({ message: "Invalid or expired token" });
  }
};
var checkSubscription = async (req, res, next) => {
  try {
    const user = req.user;
    if (!user) {
      return res.status(401).json({ message: "Authentication required" });
    }
    const currentDate = /* @__PURE__ */ new Date();
    const userSubscription = await db.query.userSubscriptions.findFirst({
      where: (subscriptions, { and: and2, eq: eq5, gt }) => and2(
        eq5(subscriptions.userId, user.id),
        eq5(subscriptions.isActive, true),
        gt(subscriptions.endDate, currentDate)
      )
    });
    const registrationDate = user.createdAt;
    const trialEndDate = new Date(registrationDate);
    trialEndDate.setDate(trialEndDate.getDate() + 3);
    const isInTrialPeriod = currentDate <= trialEndDate;
    req.subscription = userSubscription;
    req.isInTrialPeriod = isInTrialPeriod;
    req.hasActiveSubscription = !!userSubscription;
    next();
  } catch (error) {
    console.error("Subscription check error:", error);
    return res.status(500).json({ message: "Error checking subscription status" });
  }
};

// server/replitAuth.ts
import * as client from "openid-client";
import { Strategy } from "openid-client/passport";
import passport from "passport";
import session from "express-session";
import memoize from "memoizee";
import connectPg from "connect-pg-simple";
if (!process.env.REPLIT_DOMAINS) {
  throw new Error("Environment variable REPLIT_DOMAINS not provided");
}
var getOidcConfig = memoize(
  async () => {
    return await client.discovery(
      new URL(process.env.ISSUER_URL ?? "https://replit.com/oidc"),
      process.env.REPL_ID
    );
  },
  { maxAge: 3600 * 1e3 }
);
function getSession() {
  const sessionTtl = 7 * 24 * 60 * 60 * 1e3;
  const pgStore = connectPg(session);
  const sessionStore = new pgStore({
    conString: process.env.DATABASE_URL,
    createTableIfMissing: false,
    ttl: sessionTtl,
    tableName: "sessions"
  });
  return session({
    secret: process.env.SESSION_SECRET || "qr-generator-session-secret",
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: true,
      maxAge: sessionTtl
    }
  });
}
function updateUserSession(user, tokens) {
  user.claims = tokens.claims();
  user.access_token = tokens.access_token;
  user.refresh_token = tokens.refresh_token;
  user.expires_at = user.claims?.exp;
}
async function upsertUser(claims) {
  await storage.upsertUser({
    id: claims["sub"],
    email: claims["email"],
    firstName: claims["first_name"],
    lastName: claims["last_name"],
    profileImageUrl: claims["profile_image_url"]
  });
}
async function setupAuth(app2) {
  app2.set("trust proxy", 1);
  app2.use(getSession());
  app2.use(passport.initialize());
  app2.use(passport.session());
  const config = await getOidcConfig();
  const verify = async (tokens, verified) => {
    const user = {};
    updateUserSession(user, tokens);
    await upsertUser(tokens.claims());
    verified(null, user);
  };
  for (const domain of process.env.REPLIT_DOMAINS.split(",")) {
    const strategy = new Strategy(
      {
        name: `replitauth:${domain}`,
        config,
        scope: "openid email profile offline_access",
        callbackURL: `https://${domain}/api/callback`
      },
      verify
    );
    passport.use(strategy);
  }
  passport.serializeUser((user, cb) => cb(null, user));
  passport.deserializeUser((user, cb) => cb(null, user));
  app2.get("/api/login", (req, res, next) => {
    passport.authenticate(`replitauth:${req.hostname}`, {
      prompt: "login consent",
      scope: ["openid", "email", "profile", "offline_access"]
    })(req, res, next);
  });
  app2.get("/api/callback", (req, res, next) => {
    passport.authenticate(`replitauth:${req.hostname}`, {
      successReturnToOrRedirect: "/",
      failureRedirect: "/api/login"
    })(req, res, next);
  });
  app2.get("/api/logout", (req, res) => {
    req.logout(() => {
      res.redirect(
        client.buildEndSessionUrl(config, {
          client_id: process.env.REPL_ID,
          post_logout_redirect_uri: `${req.protocol}://${req.hostname}`
        }).href
      );
    });
  });
}
var isAuthenticated = async (req, res, next) => {
  const user = req.user;
  if (!req.isAuthenticated() || !user.expires_at) {
    return res.status(401).json({ message: "Unauthorized" });
  }
  const now = Math.floor(Date.now() / 1e3);
  if (now <= user.expires_at) {
    return next();
  }
  const refreshToken = user.refresh_token;
  if (!refreshToken) {
    return res.redirect("/api/login");
  }
  try {
    const config = await getOidcConfig();
    const tokenResponse = await client.refreshTokenGrant(config, refreshToken);
    updateUserSession(user, tokenResponse);
    return next();
  } catch (error) {
    return res.redirect("/api/login");
  }
};

// server/razorpay.ts
import Razorpay from "razorpay";
import crypto from "crypto";
import { eq as eq3 } from "drizzle-orm";
var razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID || "",
  key_secret: process.env.RAZORPAY_KEY_SECRET || ""
});
var createOrder = async (userId, planId) => {
  try {
    const plan = await db.query.subscriptionPlans.findFirst({
      where: eq3(subscriptionPlans.id, planId)
    });
    if (!plan) {
      throw new Error("Subscription plan not found");
    }
    const amountInPaise = Math.round(Number(plan.price) * 100);
    const options = {
      amount: amountInPaise,
      currency: plan.currency,
      receipt: `subscription_${userId}_${Date.now()}`,
      notes: {
        userId: userId.toString(),
        planId: planId.toString(),
        planName: plan.name,
        durationDays: plan.durationDays.toString()
      }
    };
    const order = await razorpay.orders.create(options);
    await db.insert(payments).values({
      userId,
      razorpayOrderId: order.id,
      amount: plan.price,
      currency: plan.currency,
      status: "created",
      paymentData: order
    });
    return {
      order,
      planDetails: plan
    };
  } catch (error) {
    console.error("Error creating Razorpay order:", error);
    throw error;
  }
};
var verifyPaymentSignature = (razorpayOrderId, razorpayPaymentId, razorpaySignature) => {
  try {
    const hmac = crypto.createHmac("sha256", process.env.RAZORPAY_KEY_SECRET || "");
    const data = `${razorpayOrderId}|${razorpayPaymentId}`;
    const generatedSignature = hmac.update(data).digest("hex");
    return generatedSignature === razorpaySignature;
  } catch (error) {
    console.error("Error verifying Razorpay signature:", error);
    return false;
  }
};
var activateSubscription = async (userId, planId, razorpayOrderId, razorpayPaymentId, razorpaySignature) => {
  try {
    const isValid = verifyPaymentSignature(razorpayOrderId, razorpayPaymentId, razorpaySignature);
    if (!isValid) {
      throw new Error("Invalid payment signature");
    }
    const payment = await db.query.payments.findFirst({
      where: eq3(payments.razorpayOrderId, razorpayOrderId)
    });
    if (!payment) {
      throw new Error("Payment record not found");
    }
    const plan = await db.query.subscriptionPlans.findFirst({
      where: eq3(subscriptionPlans.id, planId)
    });
    if (!plan) {
      throw new Error("Subscription plan not found");
    }
    await db.update(payments).set({
      razorpayPaymentId,
      razorpaySignature,
      status: "captured",
      updatedAt: /* @__PURE__ */ new Date()
    }).where(eq3(payments.razorpayOrderId, razorpayOrderId));
    await db.update(userSubscriptions).set({
      isActive: false,
      cancelledAt: /* @__PURE__ */ new Date(),
      updatedAt: /* @__PURE__ */ new Date()
    }).where(eq3(userSubscriptions.userId, userId));
    const startDate = /* @__PURE__ */ new Date();
    const endDate = /* @__PURE__ */ new Date();
    endDate.setDate(endDate.getDate() + plan.durationDays);
    const [subscription] = await db.insert(userSubscriptions).values({
      userId,
      planId,
      startDate,
      endDate,
      isActive: true,
      autoRenew: false,
      createdAt: /* @__PURE__ */ new Date(),
      updatedAt: /* @__PURE__ */ new Date()
    }).returning();
    await db.update(payments).set({
      subscriptionId: subscription.id,
      updatedAt: /* @__PURE__ */ new Date()
    }).where(eq3(payments.razorpayOrderId, razorpayOrderId));
    return subscription;
  } catch (error) {
    console.error("Error activating subscription:", error);
    throw error;
  }
};
var createFreeTrial = async (userId) => {
  try {
    const existingSubscription = await db.query.userSubscriptions.findFirst({
      where: eq3(userSubscriptions.userId, userId)
    });
    if (existingSubscription) {
      return null;
    }
    const startDate = /* @__PURE__ */ new Date();
    const endDate = /* @__PURE__ */ new Date();
    endDate.setDate(endDate.getDate() + 3);
    const [trialSubscription] = await db.insert(userSubscriptions).values({
      userId,
      planId: 1,
      // Assuming ID 1 is the free trial plan
      startDate,
      endDate,
      isActive: true,
      autoRenew: false,
      createdAt: /* @__PURE__ */ new Date(),
      updatedAt: /* @__PURE__ */ new Date()
    }).returning();
    return trialSubscription;
  } catch (error) {
    console.error("Error creating free trial:", error);
    throw error;
  }
};

// server/routes.ts
var upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024
    // limit to 5MB
  },
  fileFilter: (req, file, callback) => {
    const allowedTypes = ["image/jpeg", "image/png", "image/gif"];
    if (allowedTypes.includes(file.mimetype)) {
      callback(null, true);
    } else {
      callback(new Error("Invalid file type. Only JPEG, PNG and GIF are allowed."));
    }
  }
});
async function registerRoutes(app2) {
  await setupAuth(app2);
  app2.get("/api/auth/user", isAuthenticated, async (req, res) => {
    try {
      const userId = req.user.claims.sub;
      const user = await storage.getUser(userId);
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
      const currentDate = /* @__PURE__ */ new Date();
      const userSubscription = await db.query.userSubscriptions.findFirst({
        where: (subscriptions, { and: and2, eq: eq5, gt }) => and2(
          eq5(subscriptions.userId, user.id),
          eq5(subscriptions.isActive, true),
          gt(subscriptions.endDate, currentDate)
        ),
        with: {
          plan: true
        }
      });
      const registrationDate = user.createdAt;
      const trialEndDate = new Date(registrationDate);
      trialEndDate.setDate(trialEndDate.getDate() + 3);
      const isInTrialPeriod = currentDate <= trialEndDate;
      res.json({
        user,
        subscription: userSubscription,
        isInTrialPeriod,
        trialEndDate: isInTrialPeriod ? trialEndDate : null
      });
    } catch (error) {
      console.error("Error fetching user:", error);
      res.status(500).json({ message: "Failed to fetch user" });
    }
  });
  app2.post("/api/auth/register", async (req, res) => {
    try {
      const validatedData = insertUserSchema.safeParse(req.body);
      if (!validatedData.success) {
        return res.status(400).json({
          errors: validatedData.error.errors
        });
      }
      const { username, email, password, fullName } = validatedData.data;
      const existingUser = await db.query.users.findFirst({
        where: (users2, { or, eq: eq5 }) => or(
          eq5(users2.username, username),
          eq5(users2.email, email)
        )
      });
      if (existingUser) {
        return res.status(400).json({
          message: "Username or email already exists"
        });
      }
      const hashedPassword = await hashPassword(password);
      const [newUser] = await db.insert(users).values({
        username,
        email,
        password: hashedPassword,
        fullName,
        createdAt: /* @__PURE__ */ new Date(),
        updatedAt: /* @__PURE__ */ new Date()
      }).returning();
      await createFreeTrial(newUser.id);
      const token = generateToken(newUser);
      return res.status(201).json({
        message: "User registered successfully",
        token,
        user: {
          id: newUser.id,
          username: newUser.username,
          email: newUser.email,
          fullName: newUser.fullName
        }
      });
    } catch (error) {
      console.error("Error registering user:", error);
      return res.status(500).json({ message: "Failed to register user" });
    }
  });
  app2.post("/api/auth/login", async (req, res) => {
    try {
      const validatedData = loginSchema.safeParse(req.body);
      if (!validatedData.success) {
        return res.status(400).json({
          errors: validatedData.error.errors
        });
      }
      const { username, password } = validatedData.data;
      const user = await db.query.users.findFirst({
        where: eq4(users.username, username)
      });
      if (!user) {
        return res.status(401).json({ message: "Invalid username or password" });
      }
      const isPasswordValid = await verifyPassword(password, user.password);
      if (!isPasswordValid) {
        return res.status(401).json({ message: "Invalid username or password" });
      }
      await db.update(users).set({ lastLoginAt: /* @__PURE__ */ new Date(), updatedAt: /* @__PURE__ */ new Date() }).where(eq4(users.id, user.id));
      const token = generateToken(user);
      return res.status(200).json({
        message: "Login successful",
        token,
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          fullName: user.fullName
        }
      });
    } catch (error) {
      console.error("Error logging in:", error);
      return res.status(500).json({ message: "Failed to log in" });
    }
  });
  app2.get("/api/auth/profile", authenticateJWT, async (req, res) => {
    try {
      const user = req.user;
      const currentDate = /* @__PURE__ */ new Date();
      const userSubscription = await db.query.userSubscriptions.findFirst({
        where: (subscriptions, { and: and2, eq: eq5, gt }) => and2(
          eq5(subscriptions.userId, user.id),
          eq5(subscriptions.isActive, true),
          gt(subscriptions.endDate, currentDate)
        ),
        with: {
          plan: true
        }
      });
      const registrationDate = user.createdAt;
      const trialEndDate = new Date(registrationDate);
      trialEndDate.setDate(trialEndDate.getDate() + 3);
      const isInTrialPeriod = currentDate <= trialEndDate;
      return res.status(200).json({
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          fullName: user.fullName,
          profileImageUrl: user.profileImageUrl,
          createdAt: user.createdAt
        },
        subscription: userSubscription,
        isInTrialPeriod,
        trialEndDate: isInTrialPeriod ? trialEndDate : null
      });
    } catch (error) {
      console.error("Error fetching user profile:", error);
      return res.status(500).json({ message: "Failed to fetch user profile" });
    }
  });
  app2.post("/api/auth/reset-password-request", async (req, res) => {
    try {
      const { email } = req.body;
      if (!email) {
        return res.status(400).json({ message: "Email is required" });
      }
      const user = await db.query.users.findFirst({
        where: eq4(users.email, email)
      });
      if (!user) {
        return res.status(200).json({ message: "If your email is registered, you will receive a password reset link" });
      }
      const resetToken = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
      const resetExpires = /* @__PURE__ */ new Date();
      resetExpires.setHours(resetExpires.getHours() + 1);
      await db.update(users).set({
        resetPasswordToken: resetToken,
        resetPasswordExpires: resetExpires,
        updatedAt: /* @__PURE__ */ new Date()
      }).where(eq4(users.id, user.id));
      return res.status(200).json({
        message: "If your email is registered, you will receive a password reset link",
        // For demo purposes only - in production this should not be returned
        token: resetToken
      });
    } catch (error) {
      console.error("Error requesting password reset:", error);
      return res.status(500).json({ message: "Failed to process password reset request" });
    }
  });
  app2.post("/api/auth/reset-password", async (req, res) => {
    try {
      const validatedData = resetPasswordSchema.safeParse(req.body);
      if (!validatedData.success) {
        return res.status(400).json({
          errors: validatedData.error.errors
        });
      }
      const { token, password } = validatedData.data;
      const user = await db.query.users.findFirst({
        where: eq4(users.resetPasswordToken, token)
      });
      if (!user) {
        return res.status(400).json({ message: "Invalid or expired reset token" });
      }
      const now = /* @__PURE__ */ new Date();
      if (!user.resetPasswordExpires || user.resetPasswordExpires < now) {
        return res.status(400).json({ message: "Reset token has expired" });
      }
      const hashedPassword = await hashPassword(password);
      await db.update(users).set({
        password: hashedPassword,
        resetPasswordToken: null,
        resetPasswordExpires: null,
        updatedAt: /* @__PURE__ */ new Date()
      }).where(eq4(users.id, user.id));
      return res.status(200).json({ message: "Password has been reset successfully" });
    } catch (error) {
      console.error("Error resetting password:", error);
      return res.status(500).json({ message: "Failed to reset password" });
    }
  });
  app2.get("/api/subscription/plans", async (req, res) => {
    try {
      const plans = await db.query.subscriptionPlans.findMany({
        where: eq4(subscriptionPlans.isActive, true)
      });
      return res.status(200).json({ plans });
    } catch (error) {
      console.error("Error fetching subscription plans:", error);
      return res.status(500).json({ message: "Failed to fetch subscription plans" });
    }
  });
  app2.post("/api/subscription/create-order", authenticateJWT, async (req, res) => {
    try {
      const { planId } = req.body;
      const user = req.user;
      if (!planId) {
        return res.status(400).json({ message: "Plan ID is required" });
      }
      const orderResponse = await createOrder(user.id, planId);
      return res.status(200).json({
        orderId: orderResponse.order.id,
        planDetails: orderResponse.planDetails,
        key: process.env.RAZORPAY_KEY_ID
      });
    } catch (error) {
      console.error("Error creating subscription order:", error);
      return res.status(500).json({ message: "Failed to create subscription order" });
    }
  });
  app2.post("/api/subscription/verify-payment", authenticateJWT, async (req, res) => {
    try {
      const {
        planId,
        razorpayOrderId,
        razorpayPaymentId,
        razorpaySignature
      } = req.body;
      const user = req.user;
      if (!planId || !razorpayOrderId || !razorpayPaymentId || !razorpaySignature) {
        return res.status(400).json({ message: "Missing required fields" });
      }
      const subscription = await activateSubscription(
        user.id,
        planId,
        razorpayOrderId,
        razorpayPaymentId,
        razorpaySignature
      );
      return res.status(200).json({
        message: "Payment verified and subscription activated",
        subscription
      });
    } catch (error) {
      console.error("Error verifying payment:", error);
      return res.status(500).json({ message: "Failed to verify payment" });
    }
  });
  app2.get("/api/subscription/active", authenticateJWT, async (req, res) => {
    try {
      const user = req.user;
      const currentDate = /* @__PURE__ */ new Date();
      const subscription = await db.query.userSubscriptions.findFirst({
        where: (subscriptions, { and: and2, eq: eq5, gt }) => and2(
          eq5(subscriptions.userId, user.id),
          eq5(subscriptions.isActive, true),
          gt(subscriptions.endDate, currentDate)
        ),
        with: {
          plan: true
        }
      });
      const registrationDate = user.createdAt;
      const trialEndDate = new Date(registrationDate);
      trialEndDate.setDate(trialEndDate.getDate() + 3);
      const isInTrialPeriod = currentDate <= trialEndDate;
      return res.status(200).json({
        subscription,
        isInTrialPeriod,
        trialEndDate: isInTrialPeriod ? trialEndDate : null
      });
    } catch (error) {
      console.error("Error fetching active subscription:", error);
      return res.status(500).json({ message: "Failed to fetch active subscription" });
    }
  });
  app2.post("/api/subscription/cancel", authenticateJWT, async (req, res) => {
    try {
      const user = req.user;
      const subscription = await db.query.userSubscriptions.findFirst({
        where: (subscriptions, { and: and2, eq: eq5 }) => and2(
          eq5(subscriptions.userId, user.id),
          eq5(subscriptions.isActive, true)
        )
      });
      if (!subscription) {
        return res.status(400).json({ message: "No active subscription found" });
      }
      await db.update(userSubscriptions).set({
        isActive: false,
        cancelledAt: /* @__PURE__ */ new Date(),
        updatedAt: /* @__PURE__ */ new Date()
      }).where(eq4(userSubscriptions.id, subscription.id));
      return res.status(200).json({ message: "Subscription cancelled successfully" });
    } catch (error) {
      console.error("Error cancelling subscription:", error);
      return res.status(500).json({ message: "Failed to cancel subscription" });
    }
  });
  app2.post("/api/scan", upload.single("image"), async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ error: "No image file uploaded" });
      }
      const simulatedResult = {
        success: true,
        format: "QR_CODE",
        text: "https://example.com/product/12345"
      };
      return res.status(200).json(simulatedResult);
    } catch (error) {
      console.error("Error scanning QR code:", error);
      return res.status(500).json({ error: "Failed to scan image" });
    }
  });
  app2.post("/api/generate-batch", authenticateJWT, checkSubscription, async (req, res) => {
    try {
      const { items, settings } = req.body;
      const user = req.user;
      const hasSubscription = req.hasActiveSubscription;
      const isInTrialPeriod = req.isInTrialPeriod;
      if (!items || !Array.isArray(items) || items.length === 0) {
        return res.status(400).json({ error: "No items provided for batch generation" });
      }
      if (!hasSubscription && !isInTrialPeriod) {
        return res.status(403).json({
          error: "Subscription required",
          message: "Batch generation requires an active subscription or free trial",
          needsSubscription: true
        });
      }
      const [batchJob] = await db.insert(batchJobs).values({
        userId: user.id,
        name: settings?.name || `Batch Job ${(/* @__PURE__ */ new Date()).toISOString()}`,
        status: "completed",
        type: "qr_code",
        totalItems: items.length,
        completedItems: items.length,
        settings: settings || {},
        createdAt: /* @__PURE__ */ new Date(),
        updatedAt: /* @__PURE__ */ new Date()
      }).returning();
      const simulatedResults = items.map((item, index2) => {
        const resultItem = {
          id: index2,
          text: item.text,
          success: true,
          url: `data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==`
          // dummy 1x1 transparent PNG
        };
        db.insert(batchItems).values({
          batchJobId: batchJob.id,
          itemData: item,
          status: "completed",
          result: resultItem,
          createdAt: /* @__PURE__ */ new Date(),
          updatedAt: /* @__PURE__ */ new Date()
        }).execute();
        return resultItem;
      });
      return res.status(200).json({
        results: simulatedResults,
        batchJobId: batchJob.id
      });
    } catch (error) {
      console.error("Error generating batch QR codes:", error);
      return res.status(500).json({ error: "Failed to generate batch QR codes" });
    }
  });
  app2.post("/api/save-code", authenticateJWT, async (req, res) => {
    try {
      const { type, data, settings, name } = req.body;
      const user = req.user;
      if (!type || !data || !settings || !name) {
        return res.status(400).json({ error: "Missing required fields" });
      }
      let savedItem;
      if (type === "qr") {
        [savedItem] = await db.insert(qrCodes).values({
          userId: user.id,
          name,
          content: data.text || "",
          type: data.type || "url",
          format: settings.format || "png",
          settings,
          createdAt: /* @__PURE__ */ new Date(),
          updatedAt: /* @__PURE__ */ new Date()
        }).returning();
      } else if (type === "barcode") {
        [savedItem] = await db.insert(barcodes).values({
          userId: user.id,
          name,
          content: data.value || "",
          format: data.format || "CODE128",
          settings,
          createdAt: /* @__PURE__ */ new Date(),
          updatedAt: /* @__PURE__ */ new Date()
        }).returning();
      } else {
        return res.status(400).json({ error: "Invalid type. Must be 'qr' or 'barcode'" });
      }
      return res.status(200).json({
        success: true,
        message: "Code saved successfully",
        id: savedItem.id,
        item: savedItem
      });
    } catch (error) {
      console.error("Error saving code:", error);
      return res.status(500).json({ error: "Failed to save code" });
    }
  });
  const httpServer = createServer(app2);
  return httpServer;
}

// server/vite.ts
import express from "express";
import fs from "fs";
import path2 from "path";
import { createServer as createViteServer, createLogger } from "vite";

// vite.config.ts
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";
import runtimeErrorOverlay from "@replit/vite-plugin-runtime-error-modal";
var vite_config_default = defineConfig({
  plugins: [
    react(),
    runtimeErrorOverlay(),
    ...process.env.NODE_ENV !== "production" && process.env.REPL_ID !== void 0 ? [
      await import("@replit/vite-plugin-cartographer").then(
        (m) => m.cartographer()
      )
    ] : []
  ],
  resolve: {
    alias: {
      "@db": path.resolve(import.meta.dirname, "db"),
      "@": path.resolve(import.meta.dirname, "client", "src"),
      "@shared": path.resolve(import.meta.dirname, "shared"),
      "@assets": path.resolve(import.meta.dirname, "attached_assets")
    }
  },
  root: path.resolve(import.meta.dirname, "client"),
  build: {
    outDir: path.resolve(import.meta.dirname, "dist/public"),
    emptyOutDir: true
  }
});

// server/vite.ts
import { nanoid } from "nanoid";
var viteLogger = createLogger();
function log(message, source = "express") {
  const formattedTime = (/* @__PURE__ */ new Date()).toLocaleTimeString("en-US", {
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
    hour12: true
  });
  console.log(`${formattedTime} [${source}] ${message}`);
}
async function setupVite(app2, server) {
  const serverOptions = {
    middlewareMode: true,
    hmr: { server },
    allowedHosts: true
  };
  const vite = await createViteServer({
    ...vite_config_default,
    configFile: false,
    customLogger: {
      ...viteLogger,
      error: (msg, options) => {
        viteLogger.error(msg, options);
        process.exit(1);
      }
    },
    server: serverOptions,
    appType: "custom"
  });
  app2.use(vite.middlewares);
  app2.use("*", async (req, res, next) => {
    const url = req.originalUrl;
    try {
      const clientTemplate = path2.resolve(
        import.meta.dirname,
        "..",
        "client",
        "index.html"
      );
      let template = await fs.promises.readFile(clientTemplate, "utf-8");
      template = template.replace(
        `src="/src/main.tsx"`,
        `src="/src/main.tsx?v=${nanoid()}"`
      );
      const page = await vite.transformIndexHtml(url, template);
      res.status(200).set({ "Content-Type": "text/html" }).end(page);
    } catch (e) {
      vite.ssrFixStacktrace(e);
      next(e);
    }
  });
}
function serveStatic(app2) {
  const distPath = path2.resolve(import.meta.dirname, "public");
  if (!fs.existsSync(distPath)) {
    throw new Error(
      `Could not find the build directory: ${distPath}, make sure to build the client first`
    );
  }
  app2.use(express.static(distPath));
  app2.use("*", (_req, res) => {
    res.sendFile(path2.resolve(distPath, "index.html"));
  });
}

// server/index.ts
var app = express2();
app.use(express2.json());
app.use(express2.urlencoded({ extended: false }));
app.use((req, res, next) => {
  const start = Date.now();
  const path3 = req.path;
  let capturedJsonResponse = void 0;
  const originalResJson = res.json;
  res.json = function(bodyJson, ...args) {
    capturedJsonResponse = bodyJson;
    return originalResJson.apply(res, [bodyJson, ...args]);
  };
  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path3.startsWith("/api")) {
      let logLine = `${req.method} ${path3} ${res.statusCode} in ${duration}ms`;
      if (capturedJsonResponse) {
        logLine += ` :: ${JSON.stringify(capturedJsonResponse)}`;
      }
      if (logLine.length > 80) {
        logLine = logLine.slice(0, 79) + "\u2026";
      }
      log(logLine);
    }
  });
  next();
});
(async () => {
  const server = await registerRoutes(app);
  app.use((err, _req, res, _next) => {
    const status = err.status || err.statusCode || 500;
    const message = err.message || "Internal Server Error";
    res.status(status).json({ message });
    throw err;
  });
  if (app.get("env") === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }
  const port = 5e3;
  server.listen({
    port,
    host: "0.0.0.0",
    reusePort: true
  }, () => {
    log(`serving on port ${port}`);
  });
})();
