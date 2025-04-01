import React, { useState } from 'react';

function ScanPage() {
  const [domain, setDomain] = useState("");
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleScan = async () => {
    setLoading(true);
    try {
      const res = await fetch("http://localhost:8000/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain }),
      });
      const data = await res.json();
      setResults(data);
    } catch (err) {
      console.error("Scan failed", err);
    }
    setLoading(false);
  };

  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold mb-4">Red Team Recon Scanner</h1>
      <input
        value={domain}
        onChange={e => setDomain(e.target.value)}
        className="border p-2 rounded w-80"
        placeholder="Enter domain (e.g. example.com)"
      />
      <button
        onClick={handleScan}
        className="ml-2 px-4 py-2 bg-blue-500 text-white rounded"
      >
        Scan
      </button>

      {loading && <p className="mt-4">Scanning...</p>}

      {results && (
        <div className="mt-6">
          <h2 className="text-xl font-semibold">Results for {results.domain}</h2>
          {results.results.map((host, i) => (
            <div key={i} className="mt-4 p-4 border rounded">
              <p><strong>IP:</strong> {host.ip}</p>
              <p><strong>Organization:</strong> {host.org}</p>
              <p><strong>Country:</strong> {host.country}</p>
              <p><strong>Flagged Ports:</strong> {host.flagged_ports.join(", ")}</p>
              <p><strong>AI CVE Summary:</strong> {host.cve_summary || "None"}</p>
              {host.services.map((svc, j) => (
                <div key={j} className="mt-2">
                  <p className="font-bold">{svc.product} {svc.version}</p>
                  <ul className="list-disc ml-6">
                    {svc.extra_cves.map((cve, k) => (
                      <li key={k}>{cve.id || cve._id}: {cve.description || cve.flatDescription || "No description"}</li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default ScanPage;
