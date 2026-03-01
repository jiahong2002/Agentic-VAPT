import { useEffect, useRef } from "react";

/**
 * LiveLog — animated terminal-style progress log shown during scanning.
 *
 * Props:
 *   messages      – string[]  progress messages from backend
 *   spiderProgress – 0-100 ZAP spider percent (deployment only)
 *   scanProgress   – 0-100 ZAP active scan percent (deployment only)
 *   phase          – "design" | "development" | "deployment"
 */
export default function LiveLog({ messages, spiderProgress, scanProgress, phase }) {
  const bottomRef = useRef(null);

  // Auto-scroll to newest message
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  if (!messages || messages.length === 0) return null;

  return (
    <div className="livelog-card">
      <div className="livelog-header">
        <span className="livelog-title">
          <span className="livelog-dot" />
          Live Progress
        </span>
        {phase === "deployment" && spiderProgress > 0 && spiderProgress < 100 && (
          <span className="livelog-pct">Spider: {spiderProgress}%</span>
        )}
        {phase === "deployment" && scanProgress > 0 && scanProgress < 100 && (
          <span className="livelog-pct">Active Scan: {scanProgress}%</span>
        )}
      </div>

      {/* ZAP progress bars */}
      {phase === "deployment" && spiderProgress > 0 && (
        <div className="livelog-progress-row">
          <span className="livelog-progress-label">🕷 Spider</span>
          <div className="livelog-bar-track">
            <div className="livelog-bar-fill" style={{ width: `${spiderProgress}%` }} />
          </div>
          <span className="livelog-progress-pct">{spiderProgress}%</span>
        </div>
      )}
      {phase === "deployment" && scanProgress > 0 && (
        <div className="livelog-progress-row">
          <span className="livelog-progress-label">⚔ Active</span>
          <div className="livelog-bar-track">
            <div className="livelog-bar-fill livelog-bar-active" style={{ width: `${scanProgress}%` }} />
          </div>
          <span className="livelog-progress-pct">{scanProgress}%</span>
        </div>
      )}

      <div className="livelog-body">
        {messages.map((msg, i) => {
          const isLatest = i === messages.length - 1;
          const isDone = msg.startsWith("✅");
          const isError = msg.startsWith("✗") || msg.toLowerCase().includes("error");
          return (
            <div
              key={i}
              className={`livelog-line${isLatest ? " livelog-line-latest" : ""}${isDone ? " livelog-line-done" : ""}${isError ? " livelog-line-error" : ""}`}
            >
              <span className="livelog-prompt">›</span>
              <span className="livelog-msg">{msg}</span>
              {isLatest && !isDone && !isError && <span className="livelog-cursor" />}
            </div>
          );
        })}
        <div ref={bottomRef} />
      </div>
    </div>
  );
}
