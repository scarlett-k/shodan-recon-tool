import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App'; // ✅ This matches App.js above

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
