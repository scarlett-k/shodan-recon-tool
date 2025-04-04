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

function CVEGroup({ category, entries }) {
  const [expanded, setExpanded] = useState(false);
  const toggle = () => setExpanded(!expanded);

  // Remove any emojis/prefix to match the key in iconMap
  const categoryKey = category.replace(/^[^\w]*/, '').trim();

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
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem'
        }}
      >
        {iconMap[categoryKey]} {category} ({entries.length}) ▼
      </div>
      {expanded && (
        <ul style={{ marginLeft: '1rem' }}>
          {entries.map((cve, i) => (
            <li key={i} style={{ fontSize: '0.9rem' }}>
              <strong>{cve.id}:</strong> {cve.description}
            </li>
          ))}
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
