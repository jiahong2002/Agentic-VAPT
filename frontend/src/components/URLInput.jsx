import { useState } from "react";

export default function URLInput({ onStart, loading }) {
  const [url, setUrl] = useState("");
  const [error, setError] = useState("");

  const handleSubmit = (e) => {
    e.preventDefault();
    const trimmed = url.trim();
    if (!trimmed.startsWith("http://") && !trimmed.startsWith("https://")) {
      setError("URL must start with http:// or https://");
      return;
    }
    setError("");
    onStart(trimmed);
  };

  return (
    <div className="card url-input-card">
      <h2 className="card-title">Start VAPT Scan</h2>
      <p className="card-desc">
        Enter the URL of the web application you are authorised to test.
        The agent will run a Vulnerability Assessment first, then ask for your
        approval before any active Penetration Testing begins.
      </p>
      <div className="auth-warning">
        <span className="warn-icon">⚠</span>
        Only scan systems you have explicit written authorisation to test.
        Unauthorised scanning may be illegal.
      </div>
      <form onSubmit={handleSubmit}>
        <div className="url-form">
          <input
            type="text"
            className="url-input"
            placeholder="https://example.com"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            disabled={loading}
            autoFocus
          />
          <button type="submit" className="btn btn-primary" disabled={loading || !url.trim()}>
            {loading ? "Starting…" : "Start VA Scan →"}
          </button>
        </div>
        {error && <p className="input-error" style={{ marginTop: "0.5rem" }}>{error}</p>}
      </form>
    </div>
  );
}
