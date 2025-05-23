import React from 'react';

function extractCVEId(id = '') {
  const match = id.match(/CVE-\d{4}-\d{4,7}/i);
  return match ? match[0].toUpperCase() : null;
}

function GroupedCVEList({ cves }) {
  if (!Array.isArray(cves) || cves.length === 0) {
    return <p style={{ color: '#999' }}>No CVEs found.</p>;
  }

  return (
    <ul style={{ marginLeft: '1rem' }}>
      {cves.map((cve, i) => {
        const cveId = extractCVEId(cve.id);
        const linkUrl = cveId
          ? `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cveId}`
          : `https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=${encodeURIComponent(cve.id)}`;

        return (
          <li key={i} style={{ marginBottom: '1rem', fontSize: '0.9rem', lineHeight: '1.4' }}>
            <div><strong>ID:</strong> {cve.id}</div>
            {cve.description && (
              <div style={{ marginTop: '0.5rem' }}>
                <strong>Description:</strong> {`${cve.description.slice(0, 300)}...`}
              </div>
            )}
            {cve.cvss && <div><strong>CVSS:</strong> {cve.cvss}</div>}
            <a href={linkUrl} target="_blank" rel="noopener noreferrer" style={{ color: '#00bcd4' }}>
              View on MITRE
            </a>
          </li>
        );
      })}
    </ul>
  );
}

export default GroupedCVEList;
