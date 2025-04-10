import React, { useState } from 'react';
import ScanResults from './components/ScanResults';

function App() {
  const [domain, setDomain] = useState('');
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [hasScanned, setHasScanned] = useState(false);

  const handleScan = async () => {
    setLoading(true);
    setResults(null);
    setHasScanned(false);

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
      setResults([]);
    } finally {
      setLoading(false);
      setHasScanned(true);
    }
  };

  return (
    <div style={{
      backgroundColor: '#121212',
      color: '#f5f5f5',
      minHeight: '100vh',
      padding: '2rem',
      fontFamily: 'Segoe UI, sans-serif',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
    }}>
      <h1 style={{textAlign: 'center', fontSize: '2.5rem', marginBottom: '1rem' }}>Smart Recon Tool</h1>
      <p style={{ textAlign: 'center', marginBottom: '0.5rem', fontSize: '0.9rem', color: '#aaa' }}>
        Enter a domain or IP (e.g. <code>example.com</code> or <code>8.8.8.8</code>).<br />
        <strong>Do not</strong> include <code>https://</code> or a trailing <code>/</code>.
      </p>
      <div style={{ display: 'flex', marginBottom: '1.5rem' }}>
        <input
          type="text"
          placeholder="Enter IP or domain"
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          style={{
            padding: '0.75rem',
            borderRadius: '6px',
            border: '1px solid #555',
            backgroundColor: '#1e1e1e',
            color: '#f5f5f5',
            marginRight: '1rem',
            width: '250px',
          }}
        />
        <button
          onClick={handleScan}
          style={{
            padding: '0.75rem 1.25rem',
            backgroundColor: '#00adb5',
            color: '#fff',
            border: 'none',
            borderRadius: '6px',
            cursor: 'pointer',
            fontWeight: 'bold',
          }}
        >
          Scan
        </button>
      </div>

      {loading && <p style={{ marginTop: '1rem' }}>🔍 Scanning...</p>}

      <ScanResults results={results} hasScanned={hasScanned} />
    </div>
  );
}

export default App;
