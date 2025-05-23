import React, { useState } from 'react';
import ScanResults from './components/ScanResults';

function App() {
  const [domain, setDomain] = useState('');
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [hasScanned, setHasScanned] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');

  const handleScan = async () => {
    const inputFormat = /^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$|^(\d{1,3}\.){3}\d{1,3}$/;

    if (!inputFormat.test(domain.trim())) {
      setErrorMessage('Please enter a valid domain or IP (e.g., example.com or 8.8.8.8)');
      return;
    }

    setErrorMessage('');
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
      console.log("Full scan result:", data.results); // ✅ Debug log
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
      {/* Header & Search Section */}
      <div style={{
        width: '100%',
        maxWidth: '1000px',
        padding: '2rem 1rem 1rem',
        textAlign: 'center',
      }}>
        <h1 style={{ fontSize: '2.5rem', marginBottom: '0.5rem' }}>Shodan Recon Tool</h1>
        <p style={{ fontSize: '0.9rem', color: '#aaa', marginBottom: '1rem' }}>
          Enter a domain or IP (e.g. <code>example.com</code> or <code>8.8.8.8</code>).<br />
          <strong>Do not</strong> include <code>https://</code> or a trailing <code>/</code>.
        </p>

        <div style={{
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          gap: '1rem',
          marginBottom: '1rem',
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
              width: '280px',
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

        {errorMessage && (
          <p style={{ color: '#ff4c4c', marginTop: '0.25rem' }}>{errorMessage}</p>
        )}
        {loading && <p style={{ marginTop: '1rem' }}>🔍 Scanning...</p>}
      </div>

      {/* Results Output Section */}
      <div style={{
        width: '100%',
        maxWidth: '1100px',
        padding: '2rem 1rem',
      }}>
        <ScanResults result={results} hasScanned={hasScanned} />
      </div>
    </div>
  );
}

export default App;
