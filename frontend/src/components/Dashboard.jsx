// // import React, { useState } from 'react';
// import './Dashboard.css'; // optional: for styling if you want to separate CSS
// import React from 'react';
// function Dashboard({ results }) {
//   if (!results || results.length === 0) return <p>No results to display.</p>;

//   // Flatten and count total CVEs across all services
//   const allCVEs = results.flatMap(host =>
//     host.services.flatMap(service => service.extra_cves || [])
//   );
//   const totalCVEs = allCVEs.length;

//   return (
//     <div style={{ display: 'flex', padding: '2rem' }}>
//       {/* Left Panel: Services List */}
//       <div style={{ width: '25%', paddingRight: '1rem' }}>
//         <h3>Detected Services</h3>
//         {results.map((host, hIdx) => (
//           <div key={hIdx} style={{ marginBottom: '1rem' }}>
//             {host.services.map((svc, sIdx) => (
//               <div
//                 key={sIdx}
//                 style={{
//                   background: '#f0f0f0',
//                   padding: '0.5rem',
//                   borderRadius: '6px',
//                   marginBottom: '0.25rem',
//                 }}
//               >
//                 {svc.product} {svc.version}
//               </div>
//             ))}
//           </div>
//         ))}
//       </div>

//       {/* Middle Panel: CVE Overview */}
//       <div style={{ width: '50%', textAlign: 'center' }}>
//         <h1 style={{ fontSize: '3rem' }}>{totalCVEs}</h1>
//         <p>Total CVEs Found</p>
//       </div>

//       {/* Right Panel: Expandable CVE Detail List */}
//       <div style={{ width: '25%', paddingLeft: '1rem' }}>
//         <h3>CVEs by Service</h3>
//         {results.map((host, hIdx) => (
//           <div key={hIdx} style={{ marginBottom: '1rem' }}>
//             {host.services.map((svc, sIdx) => (
//               <details key={sIdx} style={{ marginBottom: '0.5rem' }}>
//                 <summary>
//                   {svc.product} {svc.version} ({svc.extra_cves?.length || 0})
//                 </summary>
//                 <ul>
//                   {(svc.extra_cves || []).map((cve, i) => (
//                     <li key={i}>
//                       <strong>{cve.id || cve._source?.id || 'Unknown ID'}</strong>:&nbsp;
//                       {cve.description || cve._source?.description || 'No description'}
//                     </li>
//                   ))}
//                 </ul>
//               </details>
//             ))}
//           </div>
//         ))}
//       </div>
//     </div>
//   );
// }

// export default Dashboard;
