/**
 * 🚀 SecureScan Framework - Main Application Component
 * 
 * Root React component that orchestrates the entire frontend application
 * 
 * Features:
 * - React Query provider for API state management
 * - React Router for navigation
 * - Theme provider for dark/light mode
 * - Authentication context
 * - Toast notifications
 * - Error boundaries
 * - Loading states
 * 
 * Author: SecureScan Team
 */

import React, { Suspense, useEffect } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { Toaster } from 'sonner';

// Providers and contexts
import { AuthProvider } from '@/contexts/AuthContext';
import { ThemeProvider } from '@/contexts/ThemeContext';
import { WebSocketProvider } from '@/contexts/WebSocketContext';

// Layout components
import { MainLayout } from '@/components/layout/MainLayout';
import { AuthLayout } from '@/components/layout/AuthLayout';

// Page components (lazy loaded)
const DashboardPage = React.lazy(() => import('@/pages/DashboardPage'));
const ProjectsPage = React.lazy(() => import('@/pages/ProjectsPage'));
const ProjectDetailPage = React.lazy(() => import('@/pages/ProjectDetailPage'));
const ScansPage = React.lazy(() => import('@/pages/ScansPage'));
const ScanDetailPage = React.lazy(() => import('@/pages/ScanDetailPage'));
const VulnerabilitiesPage = React.lazy(() => import('@/pages/VulnerabilitiesPage'));
const VulnerabilityDetailPage = React.lazy(() => import('@/pages/VulnerabilityDetailPage'));
const AnalyticsPage = React.lazy(() => import('@/pages/AnalyticsPage'));
const SettingsPage = React.lazy(() => import('@/pages/SettingsPage'));
const ProfilePage = React.lazy(() => import('@/pages/ProfilePage'));

// Auth pages
const LoginPage = React.lazy(() => import('@/pages/auth/LoginPage'));
const RegisterPage = React.lazy(() => import('@/pages/auth/RegisterPage'));
const ForgotPasswordPage = React.lazy(() => import('@/pages/auth/ForgotPasswordPage'));
const ResetPasswordPage = React.lazy(() => import('@/pages/auth/ResetPasswordPage'));
const VerifyEmailPage = React.lazy(() => import('@/pages/auth/VerifyEmailPage'));

// Error pages
const NotFoundPage = React.lazy(() => import('@/pages/errors/NotFoundPage'));
const ErrorPage = React.lazy(() => import('@/pages/errors/ErrorPage'));

// Components
import { LoadingSpinner } from '@/components/ui/LoadingSpinner';
import { ErrorBoundary } from '@/components/common/ErrorBoundary';
import { ProtectedRoute } from '@/components/auth/ProtectedRoute';

// =============================================================================
// ⚙️ REACT QUERY CONFIGURATION
// =============================================================================

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: (failureCount, error: any) => {
        // Don't retry on 401, 403, or 404
        if (error?.response?.status && [401, 403, 404].includes(error.response.status)) {
          return false;
        }
        return failureCount < 3;
      },
      retryDelay: (attemptIndex) => Math.min(1000 * 2 ** attemptIndex, 30000),
      staleTime: 5 * 60 * 1000, // 5 minutes
      gcTime: 10 * 60 * 1000, // 10 minutes (formerly cacheTime)
      refetchOnWindowFocus: false,
      refetchOnReconnect: true
    },
    mutations: {
      retry: (failureCount, error: any) => {
        // Don't retry mutations on 4xx errors
        if (error?.response?.status >= 400 && error?.response?.status < 500) {
          return false;
        }
        return failureCount < 2;
      }
    }
  }
});

// =============================================================================
// 🎨 LOADING COMPONENT
// =============================================================================

const AppLoadingSpinner: React.FC = () => (
  <div className="flex items-center justify-center min-h-screen bg-background">
    <div className="flex flex-col items-center space-y-4">
      <LoadingSpinner size="lg" />
      <div className="text-center">
        <h2 className="text-lg font-semibold text-foreground">Loading SecureScan</h2>
        <p className="text-sm text-muted-foreground">Please wait while we prepare your security dashboard...</p>
      </div>
    </div>
  </div>
);

// =============================================================================
// 🛡️ ERROR FALLBACK COMPONENT
// =============================================================================

const AppErrorFallback: React.FC<{ error: Error; resetError: () => void }> = ({ 
  error, 
  resetError 
}) => (
  <div className="flex items-center justify-center min-h-screen bg-background p-4">
    <div className="max-w-md w-full text-center space-y-6">
      <div className="space-y-2">
        <h1 className="text-2xl font-bold text-destructive">Something went wrong</h1>
        <p className="text-muted-foreground">
          We encountered an unexpected error. Please try refreshing the page.
        </p>
      </div>
      
      <div className="bg-muted/50 border border-border rounded-lg p-4">
        <h3 className="text-sm font-medium text-foreground mb-2">Error Details:</h3>
        <p className="text-xs text-muted-foreground font-mono break-all">
          {error.message}
        </p>
      </div>
      
      <div className="flex flex-col sm:flex-row gap-3 justify-center">
        <button
          onClick={resetError}
          className="px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 transition-colors"
        >
          Try Again
        </button>
        <button
          onClick={() => window.location.reload()}
          className="px-4 py-2 bg-secondary text-secondary-foreground rounded-md hover:bg-secondary/90 transition-colors"
        >
          Refresh Page
        </button>
      </div>
    </div>
  </div>
);

// =============================================================================
// 🛣️ ROUTE CONFIGURATION
// =============================================================================

const AppRoutes: React.FC = () => (
  <Suspense fallback={<AppLoadingSpinner />}>
    <Routes>
      {/* Public routes */}
      <Route path="/auth" element={<AuthLayout />}>
        <Route path="login" element={<LoginPage />} />
        <Route path="register" element={<RegisterPage />} />
        <Route path="forgot-password" element={<ForgotPasswordPage />} />
        <Route path="reset-password" element={<ResetPasswordPage />} />
        <Route path="verify-email" element={<VerifyEmailPage />} />
        <Route index element={<Navigate to="/auth/login" replace />} />
      </Route>

      {/* Protected routes */}
      <Route path="/" element={<ProtectedRoute />}>
        <Route element={<MainLayout />}>
          {/* Dashboard */}
          <Route index element={<DashboardPage />} />
          <Route path="dashboard" element={<Navigate to="/" replace />} />

          {/* Projects */}
          <Route path="projects" element={<ProjectsPage />} />
          <Route path="projects/:projectId" element={<ProjectDetailPage />} />

          {/* Scans */}
          <Route path="scans" element={<ScansPage />} />
          <Route path="scans/:scanId" element={<ScanDetailPage />} />

          {/* Vulnerabilities */}
          <Route path="vulnerabilities" element={<VulnerabilitiesPage />} />
          <Route path="vulnerabilities/:vulnerabilityId" element={<VulnerabilityDetailPage />} />

          {/* Analytics */}
          <Route path="analytics" element={<AnalyticsPage />} />

          {/* Settings */}
          <Route path="settings" element={<SettingsPage />} />
          <Route path="profile" element={<ProfilePage />} />
        </Route>
      </Route>

      {/* Error routes */}
      <Route path="/error" element={<ErrorPage />} />
      <Route path="*" element={<NotFoundPage />} />
    </Routes>
  </Suspense>
);

// =============================================================================
// 🚀 MAIN APPLICATION COMPONENT
// =============================================================================

const App: React.FC = () => {
  // Set up global error handling
  useEffect(() => {
    const handleUnhandledRejection = (event: PromiseRejectionEvent) => {
      console.error('Unhandled promise rejection:', event.reason);
      
      // You can send this to an error tracking service like Sentry
      // errorTracker.captureException(event.reason);
    };

    const handleError = (event: ErrorEvent) => {
      console.error('Global error:', event.error);
      
      // You can send this to an error tracking service like Sentry
      // errorTracker.captureException(event.error);
    };

    window.addEventListener('unhandledrejection', handleUnhandledRejection);
    window.addEventListener('error', handleError);

    return () => {
      window.removeEventListener('unhandledrejection', handleUnhandledRejection);
      window.removeEventListener('error', handleError);
    };
  }, []);

  return (
    <ErrorBoundary fallback={AppErrorFallback}>
      <QueryClientProvider client={queryClient}>
        <ThemeProvider>
          <AuthProvider>
            <WebSocketProvider>
              <Router>
                <div className="min-h-screen bg-background text-foreground">
                  <AppRoutes />
                  
                  {/* Global toast notifications */}
                  <Toaster
                    position="top-right"
                    expand={false}
                    richColors={true}
                    closeButton={true}
                    toastOptions={{
                      duration: 5000,
                      style: {
                        background: 'hsl(var(--background))',
                        border: '1px solid hsl(var(--border))',
                        color: 'hsl(var(--foreground))'
                      }
                    }}
                  />
                </div>
              </Router>
            </WebSocketProvider>
          </AuthProvider>
        </ThemeProvider>
      </QueryClientProvider>
    </ErrorBoundary>
  );
};

export default App;