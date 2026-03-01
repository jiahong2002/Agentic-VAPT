import { Router } from "express";
import { ScanStore } from "../store/scanStore.js";
import { generateHtmlReport } from "../report/generator.js";

const router = Router();

// GET /api/report/:scanId
router.get("/:scanId", (req, res) => {
  const scan = ScanStore.get(req.params.scanId);
  if (!scan) {
    res.status(404).json({ error: "Scan not found" });
    return;
  }
  if (!scan.report) {
    res.status(202).json({ error: "Report not ready yet", status: scan.phase });
    return;
  }

  const html = generateHtmlReport(scan.id, scan.url, scan.report, scan.findings);
  res.setHeader("Content-Type", "text/html");
  res.setHeader("X-Report-Template", "Evidence-v2");
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  res.send(html);
});

export default router;
