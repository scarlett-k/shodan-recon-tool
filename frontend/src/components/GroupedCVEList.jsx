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
        {baseTitle} ({entries.length})
      </div>
      {expanded && (
        <ul style={{ marginLeft: '1rem' }}>
          {entries.map((cve, i) => (
            <li key={i} style={{ fontSize: '0.9rem' }}>
              <strong>{cve._source?.id || cve.id || 'No ID'}:</strong>{" "}
              {cve._source?.description || cve._source?.flatDescription || 'No description'}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function normalizeTitle(title = '') {
  // Try to remove CVE/Bulletin ID from end of title
  return title.replace(/\(.*?\)|\b(SUSE|RHSA|CVE)-\d{4}.*$/, '').trim();
}

function GroupedCVEList({ cves }) {
  const grouped = {};

  cves.forEach((cve) => {
    const rawTitle = cve._source?.title || cve.id || 'Untitled';
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
