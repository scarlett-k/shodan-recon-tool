// ServiceCard.jsx
import React from 'react';
import GroupedCVEList from './GroupedCVEList';

const linkifyCVEs = (text) => {
  if (!text) return '';
  return text.replace(/CVE-\d{4}-\d{4,7}/gi, (match) => {
    return `<a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=${match}" target="_blank" rel="noopener noreferrer">${match}</a>`;
  });
};

function ServiceCard({ service }) {
  return (
    <div style={{ border: '1px solid #ddd', padding: '1rem', marginBottom: '1rem', borderRadius: '10px' }}>
      <h3 style={{ marginBottom: '0.5rem' }}>
        {service.product} {service.version}
        {service.ports && service.ports.length > 0 && (
          <> (Ports: {service.ports.join(', ')})</>
        )}
      </h3>

      {service.description && (
        <p
          dangerouslySetInnerHTML={{
            __html: linkifyCVEs(service.description),
          }}
        />
      )}

      {service.grouped_cves ? (
        <GroupedCVEList groupedCves={service.grouped_cves} />
      ) : (
        <p style={{ color: '#888' }}>No known CVEs for this service.</p>
      )}
    </div>
  );
}

export default ServiceCard;
