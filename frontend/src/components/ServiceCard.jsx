import React from 'react';
import GroupedCVEList from './GroupedCVEList';

function ServiceCard({ product, version, ports, groupedCves }) {
  return (
    <div
      style={{
        border: '1px solid #ccc',
        borderRadius: '8px',
        padding: '1rem',
        marginBottom: '1.5rem',
        backgroundColor: '#f9f9f9'
      }}
    >
      <h3 style={{ marginBottom: '0.25rem' }}>
        {product} {version && `v${version}`}
      </h3>
      <p style={{ fontSize: '0.9rem', color: '#666' }}>
        Ports: {ports.join(', ')}
      </p>

      <GroupedCVEList groupedCves={groupedCves || {}} />
    </div>
  );
}

export default ServiceCard;
