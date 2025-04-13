import React from 'react';
import VulnerabilityCard from './VulnerabilityCard';

function GlobalCVEs({ globalCVEs }) {
  if (!globalCVEs || globalCVEs.length === 0) return null;

  return (
    <div style={{
      backgroundColor: '#2a2a2a',
      border: '1px solid #444',
      padding: '1rem',
      marginTop: '2rem',
      borderRadius: '8px',
    }}>
      <h3 style={{ color: '#00adb5', marginBottom: '1rem' }}>
        🔎 Host-level Vulnerabilities (from Shodan)
      </h3>
      {globalCVEs.map((cve) => (
        <VulnerabilityCard key={cve.id} vuln={cve} />
      ))}
    </div>
  );
}

export default GlobalCVEs;