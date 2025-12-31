/**
 * 🚀 SecureScan Framework - Application Entry Point
 * 
 * Main entry point for the React application
 * 
 * Features:
 * - React 18 Concurrent Mode
 * - Strict Mode for development
 * - Error boundary integration
 * - Performance monitoring
 * - PWA registration
 * 
 * Author: SecureScan Team
 */

import React from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import './index.css';

// Development tools
if (import.meta.env.DEV) {
  // Enable React DevTools profiler in development
  // @ts-ignore
  window.__REACT_DEVTOOLS_GLOBAL_HOOK__?.settings && 
    Object.assign(window.__REACT_DEVTOOLS_GLOBAL_HOOK__.settings, {
      profilerEnabled: true
    });
}

// =============================================================================
// 🔧 APPLICATION INITIALIZATION
// =============================================================================

/**
 * Initialize and render the application
 */
async function initializeApp() {
  try {
    // Get root container
    const container = document.getElementById('root');
    if (!container) {
      throw new Error('Root container not found');
    }

    // Create React root
    const root = createRoot(container);

    // Render application
    root.render(
      <React.StrictMode>
        <App />
      </React.StrictMode>
    );

    // Log successful initialization
    console.log('🚀 SecureScan Framework initialized successfully');

    // Register PWA service worker in production
    if (import.meta.env.PROD && 'serviceWorker' in navigator) {
      try {
        const registration = await navigator.serviceWorker.register('/sw.js');
        console.log('✅ Service Worker registered:', registration);
        
        // Handle updates
        registration.addEventListener('updatefound', () => {
          const newWorker = registration.installing;
          if (newWorker) {
            newWorker.addEventListener('statechange', () => {
              if (newWorker.state === 'installed' && navigator.serviceWorker.controller) {
                // New content is available, prompt user to refresh
                if (confirm('New version available! Refresh to update?')) {
                  window.location.reload();
                }
              }
            });
          }
        });
      } catch (error) {
        console.warn('❌ Service Worker registration failed:', error);
      }
    }

  } catch (error) {
    console.error('❌ Failed to initialize application:', error);
    
    // Show error message to user
    const container = document.getElementById('root');
    if (container) {
      container.innerHTML = `
        <div style="
          display: flex;
          align-items: center;
          justify-content: center;
          min-height: 100vh;
          font-family: system-ui, -apple-system, sans-serif;
          background: #f8fafc;
          padding: 2rem;
        ">
          <div style="
            max-width: 32rem;
            width: 100%;
            text-align: center;
            background: white;
            border-radius: 0.5rem;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
            padding: 2rem;
          ">
            <h1 style="
              color: #dc2626;
              font-size: 1.5rem;
              font-weight: 600;
              margin-bottom: 1rem;
            ">
              ⚠️ Application Failed to Load
            </h1>
            <p style="
              color: #6b7280;
              margin-bottom: 1.5rem;
            ">
              We encountered an error while starting SecureScan Framework.
              Please refresh the page or contact support if the problem persists.
            </p>
            <button
              onclick="window.location.reload()"
              style="
                background: #3b82f6;
                color: white;
                border: none;
                border-radius: 0.375rem;
                padding: 0.5rem 1rem;
                font-weight: 500;
                cursor: pointer;
                transition: background-color 0.2s;
              "
              onmouseover="this.style.background='#2563eb'"
              onmouseout="this.style.background='#3b82f6'"
            >
              Refresh Page
            </button>
            <details style="margin-top: 1.5rem; text-align: left;">
              <summary style="cursor: pointer; color: #6b7280; font-size: 0.875rem;">
                Error Details
              </summary>
              <pre style="
                margin-top: 0.5rem;
                padding: 0.75rem;
                background: #f3f4f6;
                border-radius: 0.25rem;
                font-size: 0.75rem;
                overflow-x: auto;
                color: #374151;
              ">${error.toString()}</pre>
            </details>
          </div>
        </div>
      `;
    }
  }
}

// =============================================================================
// 🔍 PERFORMANCE MONITORING
// =============================================================================

/**
 * Report web vitals for performance monitoring
 */
async function reportWebVitals() {
  if (import.meta.env.PROD) {
    try {
      const { getCLS, getFID, getFCP, getLCP, getTTFB } = await import('web-vitals');
      
      getCLS(console.log);
      getFID(console.log);
      getFCP(console.log);
      getLCP(console.log);
      getTTFB(console.log);
    } catch (error) {
      console.warn('❌ Web Vitals not available:', error);
    }
  }
}

// =============================================================================
// 🚀 START APPLICATION
// =============================================================================

// Wait for DOM to be ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initializeApp);
} else {
  initializeApp();
}

// Report web vitals
reportWebVitals();

// =============================================================================
// 🌍 GLOBAL ERROR HANDLING
// =============================================================================

// Handle uncaught errors
window.addEventListener('error', (event) => {
  console.error('🔥 Global error:', event.error);
  
  // Send to error tracking service if available
  // errorTracker.captureException(event.error);
});

// Handle unhandled promise rejections
window.addEventListener('unhandledrejection', (event) => {
  console.error('🔥 Unhandled promise rejection:', event.reason);
  
  // Send to error tracking service if available
  // errorTracker.captureException(event.reason);
  
  // Prevent default behavior (console error)
  event.preventDefault();
});

// =============================================================================
// 🔧 DEVELOPMENT HELPERS
// =============================================================================

if (import.meta.env.DEV) {
  // Add development helpers to window object
  window.__SECURESCAN_DEV__ = {
    version: import.meta.env.PACKAGE_VERSION || '1.0.0',
    buildTime: new Date().toISOString(),
    environment: import.meta.env.MODE,
    apiUrl: import.meta.env.VITE_API_URL || '/api',
    wsUrl: import.meta.env.VITE_WS_URL || '/ws'
  };
  
  console.log('🔧 Development mode enabled');
  console.log('📊 App info:', window.__SECURESCAN_DEV__);
}

// =============================================================================
// 📱 PWA INSTALLATION PROMPT
// =============================================================================

let deferredPrompt: any;

window.addEventListener('beforeinstallprompt', (e) => {
  // Prevent Chrome 67 and earlier from automatically showing the prompt
  e.preventDefault();
  
  // Stash the event so it can be triggered later
  deferredPrompt = e;
  
  console.log('📱 PWA install prompt available');
  
  // Optionally, send event to analytics
  // analytics.track('pwa_install_prompt_shown');
});

window.addEventListener('appinstalled', () => {
  console.log('✅ PWA was installed');
  
  // Clear the deferredPrompt
  deferredPrompt = null;
  
  // Optionally, send event to analytics
  // analytics.track('pwa_installed');
});

// Export install prompt function for use in components
window.__showInstallPrompt = async () => {
  if (deferredPrompt) {
    // Show the prompt
    deferredPrompt.prompt();
    
    // Wait for the user to respond to the prompt
    const { outcome } = await deferredPrompt.userChoice;
    
    console.log(`📱 User ${outcome} the install prompt`);
    
    // Clear the deferredPrompt
    deferredPrompt = null;
    
    return outcome === 'accepted';
  }
  
  return false;
};