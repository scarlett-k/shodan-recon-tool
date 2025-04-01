import React from 'react';
import GroupedCVEList from './GroupedCVEList';

function ServiceCard({ service }) {
  return (
    <div style={{ border: '1px solid #ddd', padding: '1rem', marginBottom: '1rem', borderRadius: '10px' }}>
      <h3 style={{ marginBottom: '0.5rem' }}>{service.product} {service.version}</h3>

      {service.extra_cves && service.extra_cves.length > 0 ? (
        <GroupedCVEList cves={service.extra_cves} />
      ) : (
        <p style={{ color: '#888' }}>No known CVEs for this service.</p>
      )}
    </div>
  );
}

export default ServiceCard;