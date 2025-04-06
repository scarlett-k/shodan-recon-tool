import React from 'react';
import ServiceCard from './ServiceCard';

function ScanResults({ results }) {
  if (!results || results.length === 0) return <p>No results to display.</p>;
  return (
    <div style={{ marginTop: '2rem' }}>
      {results.map((r, idx) => (
        <div key={idx} style={{ borderBottom: '2px solid #ddd', paddingBottom: '1rem', marginBottom: '1rem' }}>
          <h3>IP: {r.ip}</h3>
          {/* <strong>Vulns test:</strong> {r.vulns?.join(', ') || 'None'} */}
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
          <p><strong>OS:</strong> {r.os}</p>
          <p><strong>Country:</strong> {r.country}</p>
          <p><strong>City:</strong> {r.city}</p>
          <p><strong>Ports:</strong> {(Array.isArray(r.ports) && r.ports.length > 0) ? r.ports.join(', ') : 'None'}</p>
          <p><strong>Flagged Ports:</strong> {(Array.isArray(r.flagged_ports) && r.flagged_ports.length > 0) ? r.flagged_ports.join(', ') : 'None'}</p>
          <p><strong>Tags:</strong> {(Array.isArray(r.tags) && r.tags.length > 0) ? r.tags.join(', ') : 'None'}</p>
          <p><strong>Last seen:</strong> {r.last_seen}</p>
          {/* <p><strong>AI CVE Summary:</strong> {r.cve_summary || 'None'}</p> */}
          {r.services.map((service, sIdx) => (
            <ServiceCard key={sIdx} service={service} />
          ))}
        </div>
      ))}
    </div>
    
  );

}

export default ScanResults;
