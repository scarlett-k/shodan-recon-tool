import React from 'react';

function ServiceCard({ product, version, ports, vulnerabilities = [] }) {
  return (
    <div
      style={{
        border: '1px solid #444',
        borderRadius: '8px',
        padding: '1rem',
        marginBottom: '1.5rem',
        backgroundColor: '#1e1e1e',
        color: '#eee',
      }}
    >
      <h3 style={{ color: '#00bcd4', marginBottom: '0.5rem' }}>
        {product} {version && `v${version}`} (Ports: {ports.join(', ')})
      </h3>

      {vulnerabilities.length > 0 ? (
        <ul style={{ paddingLeft: '1rem' }}>
          {vulnerabilities.map((vuln, index) => (
            <li key={index} style={{ marginBottom: '0.5rem' }}>
              <strong>{vuln.id}</strong>: {vuln.title || 'No title available'}
              {vuln.description && (
                <div style={{ fontSize: '0.9rem', color: '#ccc', marginTop: '0.25rem' }}>
                  {vuln.description.slice(0, 300)}...
                </div>
              )}
              {vuln.cvss && <div>CVSS: {vuln.cvss}</div>}
              {typeof vuln.exploit !== 'undefined' && (
                <div>Exploit Available: {vuln.exploit ? '✅ Yes' : '❌ No'}</div>
              )}
              {Array.isArray(vuln.references) && vuln.references.length > 0 && (
                <div>
                  References:
                  <ul style={{ marginLeft: '1rem' }}>
                    {vuln.references.map((url, i) => (
                      <li key={i}>
                        <a href={url} target="_blank" rel="noopener noreferrer" style={{ color: '#66ccff' }}>
                          {url}
                        </a>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </li>
          ))}
        </ul>
      ) : (
        <p style={{ color: '#888' }}>No known CVEs for this service.</p>
      )}
    </div>
  );
}

export default ServiceCard;
