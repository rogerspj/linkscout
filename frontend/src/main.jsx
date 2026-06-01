// main.jsx — the entry point React reads first.
//
// Its only job is to find the <div id="root"> in index.html and hand control
// to the App component. You will rarely need to change this file.
//
// StrictMode runs your components twice in development to catch subtle bugs
// (like side effects that shouldn't run twice). It has no effect in production.

import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './App.css'
import App from './App.jsx'

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
