import React from 'react';
import GroupedCVEList from './GroupedCVEList';
import ServiceCard from './ServiceCard';

function ScanResults({ results, hasScanned }) {
  if (!results) return null;

  print("Full scan result (fromscanresults):", results); // ✅ Debug output

  return (
    <div style={{ padding: '1rem' }}>
      <div style={{ background: '#111', padding: '1rem', borderRadius: '8px', marginBottom: '2rem' }}>
        <h2 style={{ fontSize: '1.5rem', fontWeight: 'bold' }}>IP: {results.ip}</h2>
        <p><strong>Organization:</strong> {results.org}</p>
        <p><strong>ISP:</strong> {results.isp}</p>
        <p><strong>Domains:</strong> {results.domains.join(', ') || 'None'}</p>
        <p><strong>Hostnames:</strong> {results.hostnames.join(', ') || 'None'}</p>
        <p><strong>OS:</strong> {results.os || 'Unknown'}</p>
        <p><strong>Country:</strong> {results.country}</p>
        <p><strong>City:</strong> {results.city}</p>
        <p><strong>Ports:</strong> {results.ports.join(', ') || 'None'}</p>
        <p><strong>Flagged Ports:</strong> {results.flagged_ports.join(', ') || 'None'}</p>
        <p><strong>Tags:</strong> {results.tags.join(', ') || 'None'}</p>
        <p><strong>Last seen:</strong> {results.last_seen}</p>
      </div>

      {/* ✅ TOP-LEVEL CVE SECTION */}
      {results.grouped_top_level_cves && (
        <div style={{ marginBottom: '2rem' }}>
          <h3 style={{ fontSize: '1.25rem', fontWeight: 'bold', color: '#00bcd4' }}>
            Top-level Vulnerabilities
          </h3>
          {Object.keys(results.grouped_top_level_cves).some(key => results.grouped_top_level_cves[key].length > 0) ? (
            <GroupedCVEList groupedCves={results.grouped_top_level_cves} />
          ) : (
            <p style={{ color: '#999', fontStyle: 'italic' }}>No categorized top-level CVEs found.</p>
          )}
        </div>
      )}

      {results.services && results.services.length > 0 && (
        <div>
          <h3 style={{ fontSize: '1.25rem', fontWeight: 'bold', marginBottom: '1rem' }}>
            Service Vulnerabilities
          </h3>
          {results.services.map((service, index) => (
            <ServiceCard key={index} service={service} />
          ))}
        </div>
      )}
    </div>
  );
}

export default ScanResults;