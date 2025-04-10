import React from 'react';
import ServiceCard from './ServiceCard';

function ScanResults({ results, hasScanned }) {
  if (!hasScanned) return null;
  if (!results || results.length === 0) return <p style={{ marginTop: '1rem' }}>⚠️ No results to display.</p>;

  return (
    <div style={{ marginTop: '2rem', width: '90%', maxWidth: '800px' }}>
      {results.map((r, idx) => (
        <div
          key={idx}
          style={{
            backgroundColor: '#1f1f1f',
            padding: '1.5rem',
            borderRadius: '10px',
            border: '1px solid #333',
            marginBottom: '2rem',
            boxShadow: '0 0 10px rgba(0,0,0,0.2)',
          }}
        >
          <h2 style={{ marginBottom: '0.5rem' }}>IP: {r.ip}</h2>
          <p><strong>Organization:</strong> {r.org}</p>
          {r.isp && r.isp !== r.org && (
            <p><strong>ISP:</strong> {r.isp}</p>
          )}
          {r.domains && r.domains.length > 0 && (
            <p><strong>Domains:</strong> {r.domains.join(', ')}</p>
          )}
          {r.hostnames && r.hostnames.length > 0 && r.hostnames.some(h => !r.domains.includes(h)) && (
            <p><strong>Hostnames:</strong> {r.hostnames.join(', ')}</p>
          )}
          <p><strong>OS:</strong> {r.os || 'Unknown'}</p>
          <p><strong>Country:</strong> {r.country || 'Unknown'}</p>
          <p><strong>City:</strong> {r.city || 'Unknown'}</p>
          <p><strong>Ports:</strong> {(Array.isArray(r.ports) && r.ports.length > 0) ? r.ports.join(', ') : 'None'}</p>
          <p><strong>Flagged Ports:</strong> {(Array.isArray(r.flagged_ports) && r.flagged_ports.length > 0) ? r.flagged_ports.join(', ') : 'None'}</p>
          <p><strong>Tags:</strong> {(Array.isArray(r.tags) && r.tags.length > 0) ? r.tags.join(', ') : 'None'}</p>
          <p><strong>Last seen:</strong> {r.last_seen}</p>

          {r.services.map((service, sIdx) => (
            <ServiceCard key={sIdx} service={service} />
          ))}
        </div>
      ))}
    </div>
  );
}

export default ScanResults;
