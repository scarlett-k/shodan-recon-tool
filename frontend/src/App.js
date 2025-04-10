import React, { useState } from 'react';
import ScanResults from './components/ScanResults';

function App() {
  const [domain, setDomain] = useState('');
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [hasScanned, setHasScanned] = useState(false); // NEW

  const handleScan = async () => {
    setLoading(true);
    setResults(null);
    setHasScanned(false); // Reset before scanning

    try {
      const response = await fetch('https://shodan-recon-tool.onrender.com/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain }),
      });

      const data = await response.json();
      setResults(data.results);
    } catch (err) {
      console.error('Scan failed:', err);
      setResults([]); // Show "no results" if scan fails gracefully
    } finally {
      setLoading(false);
      setHasScanned(true); // Mark as scanned after request completes
    }
  };

  return (
    <div style={{ padding: '2rem', fontFamily: 'sans-serif' }}>
      <h1>Smart Recon Tool</h1>
      <input
        type="text"
        placeholder="Enter domain (e.g. example.com)"
        value={domain}
        onChange={(e) => setDomain(e.target.value)}
        style={{ padding: '0.5rem', marginRight: '1rem' }}
      />
      <button onClick={handleScan}>Scan</button>

      {loading && <p>Scanning...</p>}

      <ScanResults results={results} hasScanned={hasScanned} />
    </div>
  );
}

export default App;
