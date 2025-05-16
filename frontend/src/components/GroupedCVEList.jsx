import React, { useState } from 'react';
import { PiExclamationMarkFill } from "react-icons/pi";
import { IoIosWarning } from "react-icons/io";
import { BsQuestionCircle } from "react-icons/bs";
import { IoDocumentTextSharp } from "react-icons/io5";
import { PiFileMagnifyingGlassFill } from "react-icons/pi";

const iconMap = {
  "Critical": <PiExclamationMarkFill color="#ad1f1f" />,
  "High Severity": <IoIosWarning color="#ed931c" />,
  "Known Patterns": <PiFileMagnifyingGlassFill color="#4a4b70" />,
  "Vendor Advisories": <IoDocumentTextSharp color="#595c59" />,
  "Other": <BsQuestionCircle color="gray" />
};

// Utility to extract CVE-style ID from anything like UBUNTU-CVE-2024-XXXX
function extractCVEId(id = '') {
  const match = id.match(/CVE-\d{4}-\d{4,7}/i);
  return match ? match[0].toUpperCase() : null;
}

function CVEGroup({ category, entries }) {
  const [expanded, setExpanded] = useState(false);
  const toggle = () => setExpanded(!expanded);
  const categoryKey = category.replace(/^[^\w]*/, '').trim();

  return (
    <div style={{ marginBottom: '1rem' }}>
      <div
        onClick={toggle}
        style={{
          cursor: 'pointer',
          fontWeight: 'bold',
          background: '#222',
          color: '#fff',
          padding: '0.5rem',
          borderRadius: '5px',
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
          border: '1px solid #444',
          transition: 'background 0.2s',
        }}
        onMouseEnter={(e) => (e.currentTarget.style.background = '#333')}
        onMouseLeave={(e) => (e.currentTarget.style.background = '#222')}
      >
        {iconMap[categoryKey]} {category} ({entries.length}) ▼
      </div>
      {expanded && (
        <ul style={{ marginLeft: '1rem' }}>
          {entries.map((cve, i) => {
            const cveId = extractCVEId(cve.id);
            const linkUrl = cveId
            ? `https://nvd.nist.gov/vuln/detail/${cveId}`
            : `https://nvd.nist.gov/vuln/search/results?query=${encodeURIComponent(cve.id)}`;


            return (
              <li key={i} style={{ marginBottom: '1rem', fontSize: '0.9rem', lineHeight: '1.4' }}>
                <div><strong>ID:</strong> {cve.id}</div>

                {cve.title && (
                  <div style={{ marginTop: '0.25rem' }}>
                    <strong>Title:</strong>{' '}
                    <a
                      href={linkUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      style={{
                        textDecoration: 'none',
                        color: 'inherit',
                        borderBottom: '1px dotted #888',
                        transition: 'color 0.2s',
                      }}
                      onMouseEnter={(e) => (e.target.style.color = '#007acc')}
                      onMouseLeave={(e) => (e.target.style.color = 'inherit')}
                    >
                      {cve.title}
                    </a>
                  </div>
                )}

                {cve.description && (
                  <div style={{ marginTop: '0.5rem' }}>
                    <strong>Description:</strong>{' '}
                    {`${cve.description.slice(0, 300)}...`}
                  </div>
                )}

                {cve.cvss && <div><strong>CVSS:</strong> {cve.cvss}</div>}
                {typeof cve.exploit !== 'undefined' && (
                  <div><strong>Exploit Available:</strong> {cve.exploit ? '✅ Yes' : '❌ No'}</div>
                )}
                {Array.isArray(cve.references) && cve.references.length > 0 && (
                  <div><strong>References:</strong>
                    <ul style={{ marginLeft: '1rem' }}>
                      {cve.references.map((url, idx) => (
                        <li key={idx}>
                          <a href={url} target="_blank" rel="noopener noreferrer">{url}</a>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}

function normalizeId(id = '') {
  return id.replace(/^[A-Z]+:/, '').toUpperCase(); // e.g. OSV:CVE-2024-1234 => CVE-2024-1234
}

function GroupedCVEList({ groupedCves }) {
  const dedupedGrouped = {};

  for (const [category, cveList] of Object.entries(groupedCves)) {
    const seen = new Set();
    const uniqueEntries = [];

    for (const cve of cveList) {
      const baseId = normalizeId(cve.id);
      if (!seen.has(baseId)) {
        seen.add(baseId);
        uniqueEntries.push({ ...cve, id: baseId });
      }
    }

    dedupedGrouped[category] = uniqueEntries;
  }

  return (
    <div>
      {Object.entries(dedupedGrouped).map(([category, entries], idx) => (
        <CVEGroup key={idx} category={category} entries={entries} />
      ))}
    </div>
  );
}

export default GroupedCVEList;
