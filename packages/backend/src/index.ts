import "dotenv/config";
import http from "http";
import express from "express";
import cors from "cors";
import { WSManager } from "./websocket.js";
import { createScanRouter } from "./routes/scan.js";
import approveRouter from "./routes/approve.js";
import reportRouter from "./routes/report.js";

const PORT = parseInt(process.env.PORT ?? "3001", 10);

const app = express();
app.use(cors({ origin: process.env.FRONTEND_ORIGIN ?? "http://localhost:5173" }));
app.use(express.json());

const server = http.createServer(app);
const wsManager = new WSManager(server);

// Routes
app.use("/api/scan", createScanRouter(wsManager));
app.use("/api/approve", approveRouter);
app.use("/api/report", reportRouter);

// Health check
app.get("/health", (_req, res) =>
  res.json({ ok: true, backend_version: "evidence-v2-2026-03-02" })
);

server.listen(PORT, () => {
  console.log(`Backend listening on http://localhost:${PORT}`);
});
