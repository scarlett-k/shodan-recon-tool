import React, { useState } from 'react';

function CVEGroup({ baseTitle, entries }) {
  const [expanded, setExpanded] = useState(false);
  const toggle = () => setExpanded(!expanded);

  return (
    <div style={{ marginBottom: '1rem' }}>
      <div
        onClick={toggle}
        style={{
          cursor: 'pointer',
          fontWeight: 'bold',
          background: '#f3f3f3',
          padding: '0.5rem',
          borderRadius: '5px',
        }}
      >
        {baseTitle} ({entries.length}) ▼
      </div>
      {expanded && (
        <ul style={{ marginLeft: '1rem' }}>
          {entries.map((cve, i) => {
            const desc = cve._source?.description || cve._source?.flatDescription || 'No description';
            const cveId = cve._source?.id || cve.id || cve._id || i;
            return (
              <li key={cveId}>
                <strong>{cveId}:</strong> {desc}
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}

function normalizeTitle(title = '') {
  return title
    .replace(/\(.*?\)/g, '') // Remove text in parentheses
    .replace(/\b(SUSE|RHSA|CVE|VERACODE|OPENVAS)[:-]?\d{4}.*$/i, '') // Remove known ID patterns
    .trim();
}

function GroupedCVEList({ cves }) {
  const grouped = {};
  const seenIds = new Set();

  // Deduplicate first
  const uniqueCVEs = cves.filter((cve) => {
    const id = cve._source?.id || cve.id || cve._id;
    if (seenIds.has(id)) return false;
    seenIds.add(id);
    return true;
  });

  uniqueCVEs.forEach((cve) => {
    const rawTitle = cve._source?.title || cve.title || cve.id || 'Untitled';
    const baseTitle = normalizeTitle(rawTitle);
    if (!grouped[baseTitle]) grouped[baseTitle] = [];
    grouped[baseTitle].push(cve);
  });

  return (
    <div>
      {Object.entries(grouped).map(([baseTitle, entries], idx) => (
        <CVEGroup key={idx} baseTitle={baseTitle} entries={entries} />
      ))}
    </div>
  );
}

export default GroupedCVEList;
