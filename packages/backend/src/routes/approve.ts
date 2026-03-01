import { Router } from "express";
import { ScanStore } from "../store/scanStore.js";

const router = Router();

// POST /api/approve/:scanId
// Body: { approvalId: string, approved: boolean }
router.post("/:scanId", (req, res) => {
  const { scanId } = req.params;
  const { approvalId, approved } = req.body as { approvalId?: string; approved?: boolean };

  if (!approvalId || typeof approved !== "boolean") {
    res.status(400).json({ error: "approvalId and approved (boolean) are required" });
    return;
  }

  const scan = ScanStore.get(scanId);
  if (!scan || !scan.gate) {
    res.status(404).json({ error: "Scan not found or no pending approval" });
    return;
  }

  const resolved = scan.gate.resolve(approvalId, approved);
  if (!resolved) {
    res.status(404).json({ error: "Approval ID not found or already resolved" });
    return;
  }

  res.json({ ok: true, approved });
});

export default router;
