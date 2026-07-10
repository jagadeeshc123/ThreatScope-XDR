import { lazy, Suspense } from 'react';
import { BrowserRouter as Router, Routes, Route, Outlet } from 'react-router-dom';
import { Sidebar } from './components/layout/Sidebar';
import { Topbar } from './components/layout/Topbar';

import { Dashboard } from './pages/Dashboard';
import { Targets } from './pages/Targets';
import { Scans } from './pages/Scans';
import { NewScan } from './pages/NewScan';
import { Reports } from './pages/Reports';
import { LandingPage } from './pages/LandingPage';
import { SearchResultsPage } from './pages/SearchResults';
import { Policies } from './pages/Policies';
import { Profile } from './pages/Profile';
import { Notifications } from './pages/Notifications';
import { Settings } from './pages/Settings';
import { Toaster } from 'sonner';

const ApiSecurityOverview = lazy(() => import('./pages/api-security/ApiSecurityOverview').then(module => ({ default: module.ApiSecurityOverview })));
const NewApiAssessment = lazy(() => import('./pages/api-security/NewApiAssessment').then(module => ({ default: module.NewApiAssessment })));
const ImportApiDefinition = lazy(() => import('./pages/api-security/ImportApiDefinition').then(module => ({ default: module.ImportApiDefinition })));
const ApiAssessmentDetails = lazy(() => import('./pages/api-security/ApiAssessmentDetails').then(module => ({ default: module.ApiAssessmentDetails })));
const EndpointInventory = lazy(() => import('./pages/api-security/EndpointInventory').then(module => ({ default: module.EndpointInventory })));
const JwtAnalyzer = lazy(() => import('./pages/api-security/JwtAnalyzer').then(module => ({ default: module.JwtAnalyzer })));
const JwtAnalysisDetails = lazy(() => import('./pages/api-security/JwtAnalysisDetails').then(module => ({ default: module.JwtAnalysisDetails })));
const AuthorizationMatrix = lazy(() => import('./pages/api-security/authorization/AuthorizationMatrix').then(module => ({ default: module.AuthorizationMatrix })));
const AuthorizationReviews = lazy(() => import('./pages/api-security/authorization/AuthorizationReviews').then(module => ({ default: module.AuthorizationReviews })));
const BusinessFlowList = lazy(() => import('./pages/api-security/business-flows/BusinessFlowList').then(module => ({ default: module.BusinessFlowList })));
const BusinessFlowEditor = lazy(() => import('./pages/api-security/business-flows/BusinessFlowEditor').then(module => ({ default: module.BusinessFlowEditor })));
const BusinessFlowDetails = lazy(() => import('./pages/api-security/business-flows/BusinessFlowDetails').then(module => ({ default: module.BusinessFlowDetails })));

function Layout() {
  return (
    <div className="flex min-h-screen overflow-hidden bg-background text-foreground">
      <Sidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar />
        <main className="min-w-0 flex-1 overflow-y-auto overflow-x-hidden">
          <Outlet />
        </main>
      </div>
    </div>
  );
}

function LoadingRoute() {
  return <div className="p-6 text-sm text-muted-foreground">Loading API Security...</div>;
}

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<LandingPage />} />
        <Route element={<Layout />}>
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/targets" element={<Targets />} />
          <Route path="/scans" element={<Scans />} />
          <Route path="/scans/new" element={<NewScan />} />
          <Route path="/api-security" element={<Suspense fallback={<LoadingRoute />}><ApiSecurityOverview /></Suspense>} />
          <Route path="/api-security/new" element={<Suspense fallback={<LoadingRoute />}><NewApiAssessment /></Suspense>} />
          <Route path="/api-security/assessments/:assessmentId" element={<Suspense fallback={<LoadingRoute />}><ApiAssessmentDetails /></Suspense>} />
          <Route path="/api-security/assessments/:assessmentId/import" element={<Suspense fallback={<LoadingRoute />}><ImportApiDefinition /></Suspense>} />
          <Route path="/api-security/assessments/:assessmentId/endpoints" element={<Suspense fallback={<LoadingRoute />}><EndpointInventory /></Suspense>} />
          <Route path="/api-security/jwt" element={<Suspense fallback={<LoadingRoute />}><JwtAnalyzer /></Suspense>} />
          <Route path="/api-security/jwt/:analysisId" element={<Suspense fallback={<LoadingRoute />}><JwtAnalysisDetails /></Suspense>} />
          <Route path="/api-security/assessments/:assessmentId/authorization" element={<Suspense fallback={<LoadingRoute />}><AuthorizationMatrix /></Suspense>} />
          <Route path="/api-security/assessments/:assessmentId/authorization-reviews" element={<Suspense fallback={<LoadingRoute />}><AuthorizationReviews /></Suspense>} />
          <Route path="/api-security/assessments/:assessmentId/business-flows" element={<Suspense fallback={<LoadingRoute />}><BusinessFlowList /></Suspense>} />
          <Route path="/api-security/business-flows/:flowId" element={<Suspense fallback={<LoadingRoute />}><BusinessFlowDetails /></Suspense>} />
          <Route path="/api-security/business-flows/:flowId/edit" element={<Suspense fallback={<LoadingRoute />}><BusinessFlowEditor /></Suspense>} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/policies" element={<Policies />} />
          <Route path="/search" element={<SearchResultsPage />} />
          <Route path="/profile" element={<Profile />} />
          <Route path="/notifications" element={<Notifications />} />
          <Route path="/settings" element={<Settings />} />
        </Route>
      </Routes>
      <Toaster theme="dark" position="bottom-right" />
    </Router>
  );
}

export default App;
