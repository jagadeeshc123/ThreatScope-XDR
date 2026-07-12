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
const SocOverview = lazy(() => import('./pages/soc-monitor/SocOverview').then(module => ({ default: module.SocOverview })));
const LogSources = lazy(() => import('./pages/soc-monitor/LogSources').then(module => ({ default: module.LogSources })));
const LogImports = lazy(() => import('./pages/soc-monitor/LogImports').then(module => ({ default: module.LogImports })));
const EventExplorer = lazy(() => import('./pages/soc-monitor/EventExplorer').then(module => ({ default: module.EventExplorer })));
const EventDetails = lazy(() => import('./pages/soc-monitor/EventDetails').then(module => ({ default: module.EventDetails })));
const DetectionRules = lazy(() => import('./pages/soc-monitor/DetectionRules').then(module => ({ default: module.DetectionRules })));
const AlertList = lazy(() => import('./pages/soc-monitor/AlertList').then(module => ({ default: module.AlertList })));
const AlertDetails = lazy(() => import('./pages/soc-monitor/AlertDetails').then(module => ({ default: module.AlertDetails })));
const LogSimulator = lazy(() => import('./pages/soc-monitor/LogSimulator').then(module => ({ default: module.LogSimulator })));
const LocalBlocklist = lazy(() => import('./pages/soc-monitor/LocalBlocklist').then(module => ({ default: module.LocalBlocklist })));
const SocReports = lazy(() => import('./pages/soc-monitor/SocReports').then(module => ({ default: module.SocReports })));
const SocReportDetails = lazy(() => import('./pages/soc-monitor/SocReportDetails').then(module => ({ default: module.SocReportDetails })));
const DocumentThreatOverview = lazy(() => import('./pages/document-threats/DocumentThreatOverview').then(module => ({ default: module.DocumentThreatOverview })));
const AnalyzeDocument = lazy(() => import('./pages/document-threats/AnalyzeDocument').then(module => ({ default: module.AnalyzeDocument })));
const DocumentAnalysisList = lazy(() => import('./pages/document-threats/DocumentAnalysisList').then(module => ({ default: module.DocumentAnalysisList })));
const DocumentAnalysisDetails = lazy(() => import('./pages/document-threats/DocumentAnalysisDetails').then(module => ({ default: module.DocumentAnalysisDetails })));
const DocumentReports = lazy(() => import('./pages/document-threats/DocumentReports').then(module => ({ default: module.DocumentReports })));
const DocumentReportDetails = lazy(() => import('./pages/document-threats/DocumentReportDetails').then(module => ({ default: module.DocumentReportDetails })));
const PhishingOverview = lazy(() => import('./pages/phishing-defense/PhishingOverview').then(m => ({default:m.PhishingOverview})));
const AnalyzePhishing = lazy(() => import('./pages/phishing-defense/AnalyzePhishing').then(m => ({default:m.AnalyzePhishing})));
const PhishingAnalysisList = lazy(() => import('./pages/phishing-defense/PhishingAnalysisList').then(m => ({default:m.PhishingAnalysisList})));
const PhishingAnalysisDetails = lazy(() => import('./pages/phishing-defense/PhishingAnalysisDetails').then(m => ({default:m.PhishingAnalysisDetails})));
const PhishingWatchlist = lazy(() => import('./pages/phishing-defense/PhishingWatchlist').then(m => ({default:m.PhishingWatchlist})));
const PhishingModelInfo = lazy(() => import('./pages/phishing-defense/PhishingModelInfo').then(m => ({default:m.PhishingModelInfo})));
const PhishingReports = lazy(() => import('./pages/phishing-defense/PhishingReports').then(m => ({default:m.PhishingReports})));
const PhishingReportDetails = lazy(() => import('./pages/phishing-defense/PhishingReportDetails').then(m => ({default:m.PhishingReportDetails})));

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
  return <div className="p-6 text-sm text-muted-foreground">Loading module...</div>;
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
          <Route path="/soc" element={<Suspense fallback={<LoadingRoute />}><SocOverview /></Suspense>} />
          <Route path="/soc/sources" element={<Suspense fallback={<LoadingRoute />}><LogSources /></Suspense>} />
          <Route path="/soc/imports" element={<Suspense fallback={<LoadingRoute />}><LogImports /></Suspense>} />
          <Route path="/soc/events" element={<Suspense fallback={<LoadingRoute />}><EventExplorer /></Suspense>} />
          <Route path="/soc/events/:eventId" element={<Suspense fallback={<LoadingRoute />}><EventDetails /></Suspense>} />
          <Route path="/soc/rules" element={<Suspense fallback={<LoadingRoute />}><DetectionRules /></Suspense>} />
          <Route path="/soc/alerts" element={<Suspense fallback={<LoadingRoute />}><AlertList /></Suspense>} />
          <Route path="/soc/alerts/:alertId" element={<Suspense fallback={<LoadingRoute />}><AlertDetails /></Suspense>} />
          <Route path="/soc/simulator" element={<Suspense fallback={<LoadingRoute />}><LogSimulator /></Suspense>} />
          <Route path="/soc/blocklist" element={<Suspense fallback={<LoadingRoute />}><LocalBlocklist /></Suspense>} />
          <Route path="/soc/reports" element={<Suspense fallback={<LoadingRoute />}><SocReports /></Suspense>} />
          <Route path="/soc/reports/:reportId" element={<Suspense fallback={<LoadingRoute />}><SocReportDetails /></Suspense>} />
          <Route path="/document-threats" element={<Suspense fallback={<LoadingRoute />}><DocumentThreatOverview /></Suspense>} />
          <Route path="/document-threats/analyze" element={<Suspense fallback={<LoadingRoute />}><AnalyzeDocument /></Suspense>} />
          <Route path="/document-threats/analyses" element={<Suspense fallback={<LoadingRoute />}><DocumentAnalysisList /></Suspense>} />
          <Route path="/document-threats/analyses/:analysisId" element={<Suspense fallback={<LoadingRoute />}><DocumentAnalysisDetails /></Suspense>} />
          <Route path="/document-threats/reports" element={<Suspense fallback={<LoadingRoute />}><DocumentReports /></Suspense>} />
          <Route path="/document-threats/reports/:reportId" element={<Suspense fallback={<LoadingRoute />}><DocumentReportDetails /></Suspense>} />
          <Route path="/phishing-defense" element={<Suspense fallback={<LoadingRoute />}><PhishingOverview /></Suspense>} />
          <Route path="/phishing-defense/analyze" element={<Suspense fallback={<LoadingRoute />}><AnalyzePhishing /></Suspense>} />
          <Route path="/phishing-defense/analyses" element={<Suspense fallback={<LoadingRoute />}><PhishingAnalysisList /></Suspense>} />
          <Route path="/phishing-defense/analyses/:analysisId" element={<Suspense fallback={<LoadingRoute />}><PhishingAnalysisDetails /></Suspense>} />
          <Route path="/phishing-defense/watchlist" element={<Suspense fallback={<LoadingRoute />}><PhishingWatchlist /></Suspense>} />
          <Route path="/phishing-defense/model" element={<Suspense fallback={<LoadingRoute />}><PhishingModelInfo /></Suspense>} />
          <Route path="/phishing-defense/reports" element={<Suspense fallback={<LoadingRoute />}><PhishingReports /></Suspense>} />
          <Route path="/phishing-defense/reports/:reportId" element={<Suspense fallback={<LoadingRoute />}><PhishingReportDetails /></Suspense>} />
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
