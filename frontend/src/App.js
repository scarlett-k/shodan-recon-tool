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
      fontFamily: 'Segoe UI, sans-serif',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
    }}>
      {/* Sticky Header Section */}
      <div style={{
        width: '100%',
        maxWidth: '1000px',
        position: 'sticky',
        top: 0,
        backgroundColor: '#121212',
        padding: '2rem 1rem 1rem',
        zIndex: 1000,
        borderBottom: '1px solid #2a2a2a',
      }}>
        <h1 style={{ textAlign: 'center', fontSize: '2.5rem', marginBottom: '0.5rem' }}>Shodan Recon Tool</h1>
        <p style={{ textAlign: 'center', fontSize: '0.9rem', color: '#aaa', marginBottom: '1rem' }}>
          Enter a domain or IP (e.g. <code>example.com</code> or <code>8.8.8.8</code>).<br />
          <strong>Do not</strong> include <code>https://</code> or a trailing <code>/</code>.
        </p>
        <div style={{
          display: 'flex',
          flexDirection: 'row',
          justifyContent: 'center',
          flexWrap: 'wrap',
          gap: '1rem',
        }}>
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
              width: '250px',
              flex: '1 0 auto'
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
              flexShrink: 0
            }}
          >
            Scan
          </button>
        </div>
        {loading && <p style={{ textAlign: 'center', marginTop: '1rem' }}>🔍 Scanning...</p>}
      </div>

      {/* Scrollable Results Section */}
      <div style={{
        width: '100%',
        maxWidth: '1000px',
        padding: '2rem 1rem',
        overflowY: 'auto',
        flexGrow: 1,
      }}>
        <ScanResults results={results} hasScanned={hasScanned} />
      </div>
    </div>
  );
}

export default App;
