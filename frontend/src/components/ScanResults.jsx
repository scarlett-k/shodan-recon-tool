import React from 'react';
import GroupedCVEList from './GroupedCVEList';
import ServiceCard from './ServiceCard';

function ScanResults({ result }) {
  if (!result) return null;
  print("Full scan result:", result);
  return (
    <div style={{ padding: '1rem' }}>
      <div style={{ background: '#111', padding: '1rem', borderRadius: '8px', marginBottom: '2rem' }}>
        <h2 style={{ fontSize: '1.5rem', fontWeight: 'bold' }}>IP: {result.ip}</h2>
        <p><strong>Organization:</strong> {result.org}</p>
        <p><strong>ISP:</strong> {result.isp}</p>
        <p><strong>Domains:</strong> {result.domains.join(', ') || 'None'}</p>
        <p><strong>Hostnames:</strong> {result.hostnames.join(', ') || 'None'}</p>
        <p><strong>OS:</strong> {result.os || 'Unknown'}</p>
        <p><strong>Country:</strong> {result.country}</p>
        <p><strong>City:</strong> {result.city}</p>
        <p><strong>Ports:</strong> {result.ports.join(', ') || 'None'}</p>
        <p><strong>Flagged Ports:</strong> {result.flagged_ports.join(', ') || 'None'}</p>
        <p><strong>Tags:</strong> {result.tags.join(', ') || 'None'}</p>
        <p><strong>Last seen:</strong> {result.last_seen}</p>
      </div>

      {/* ✅ TOP-LEVEL CVE SECTION */}
      {result.grouped_top_level_cves && (
        <div style={{ marginBottom: '2rem' }}>
          <h3 style={{ fontSize: '1.25rem', fontWeight: 'bold', color: '#00bcd4' }}>
            Top-level Vulnerabilities
          </h3>
          {Object.keys(result.grouped_top_level_cves).some(key => result.grouped_top_level_cves[key].length > 0) ? (
            <GroupedCVEList groupedCves={result.grouped_top_level_cves} />
          ) : (
            <p style={{ color: '#999', fontStyle: 'italic' }}>No categorized top-level CVEs found.</p>
          )}
        </div>
      )}

      {result.services && result.services.length > 0 && (
        <div>
          <h3 style={{ fontSize: '1.25rem', fontWeight: 'bold', marginBottom: '1rem' }}>
            Service Vulnerabilities
          </h3>
          {result.services.map((service, index) => (
            <ServiceCard key={index} service={service} />
          ))}
        </div>
      )}
    </div>
  );
}

export default ScanResults;
