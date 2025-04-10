import React from 'react';
import GroupedCVEList from './GroupedCVEList';

const linkifyCVEs = (text) => {
  if (!text) return '';
  return text.replace(/CVE-\d{4}-\d{4,7}/gi, (match) => {
    return `<a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=${match}" target="_blank" rel="noopener noreferrer" style="color:#00adb5;">${match}</a>`;
  });
};

function ServiceCard({ service }) {
  return (
    <div style={{
      backgroundColor: '#2a2a2a',
      border: '1px solid #444',
      padding: '1rem',
      marginTop: '1rem',
      borderRadius: '8px',
    }}>
      <h3 style={{ marginBottom: '0.5rem', color: '#00adb5' }}>
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
          style={{ lineHeight: '1.5', color: '#ccc' }}
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
