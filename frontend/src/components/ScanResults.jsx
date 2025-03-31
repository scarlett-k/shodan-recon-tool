import React from 'react';
import ServiceCard from './ServiceCard';

function ScanResults({ results }) {
  if (!results || results.length === 0) return <p>No results to display.</p>;

  return (
    <div style={{ marginTop: '2rem' }}>
      {results.map((r, idx) => (
        <div key={idx} style={{ borderBottom: '2px solid #ddd', paddingBottom: '1rem', marginBottom: '1rem' }}>
          <h3>IP: {r.ip}</h3>
          <p><strong>Organization:</strong> {r.org}</p>
          <p><strong>Country:</strong> {r.country}</p>
          <p><strong>Flagged Ports:</strong> {r.flagged_ports.join(', ') || 'None'}</p>
          <p><strong>AI CVE Summary:</strong> {r.cve_summary || 'None'}</p>

          {r.services.map((service, sIdx) => (
            <ServiceCard key={sIdx} service={service} />
          ))}
        </div>
      ))}
    </div>
  );
}

export default ScanResults;
