import { EventEmitter } from "events";

export interface ApprovalRequest {
  id: string;
  scanId: string;
  type: "exploit_plan" | "exploit_attempt";
  message: string;
  data: unknown;
}

type ApprovalResolver = (approved: boolean) => void;

const APPROVAL_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes

export class ApprovalGate extends EventEmitter {
  private scanId: string;
  private pendingResolvers = new Map<string, ApprovalResolver>();

  constructor(scanId: string) {
    super();
    this.scanId = scanId;
  }

  /**
   * Pauses the pipeline and waits for a human to approve or deny.
   * Resolves to true (approved) or false (denied/timed-out).
   */
  async requestApproval(request: Omit<ApprovalRequest, "id" | "scanId">): Promise<boolean> {
    const id = `approval-${Date.now()}-${Math.random().toString(36).slice(2)}`;
    const fullRequest: ApprovalRequest = { ...request, id, scanId: this.scanId };

    // Broadcast to UI via WebSocket
    this.emit("approval_required", fullRequest);

    return new Promise<boolean>((resolve) => {
      this.pendingResolvers.set(id, resolve);

      // Auto-deny after timeout
      const timer = setTimeout(() => {
        if (this.pendingResolvers.has(id)) {
          this.pendingResolvers.delete(id);
          this.emit("approval_timeout", { id });
          resolve(false);
        }
      }, APPROVAL_TIMEOUT_MS);

      // Clean up timer if resolved early
      const originalResolve = resolve;
      this.pendingResolvers.set(id, (approved) => {
        clearTimeout(timer);
        originalResolve(approved);
      });
    });
  }

  /**
   * Called by the Express route when the human clicks Approve or Deny.
   */
  resolve(approvalId: string, approved: boolean): boolean {
    const resolver = this.pendingResolvers.get(approvalId);
    if (!resolver) return false;
    this.pendingResolvers.delete(approvalId);
    this.emit("approval_resolved", { id: approvalId, approved });
    resolver(approved);
    return true;
  }

  get hasPending(): boolean {
    return this.pendingResolvers.size > 0;
  }
}
