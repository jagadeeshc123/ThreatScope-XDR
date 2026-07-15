import { lazy, Suspense } from 'react';
import { BrowserRouter as Router, Routes, Route, Outlet } from 'react-router-dom';
import { Sidebar } from './components/layout/Sidebar';
import { Topbar } from './components/layout/Topbar';

import { Dashboard } from './pages/Dashboard';
import { Targets } from './pages/Targets';
import { Scans } from './pages/Scans';
import { NewScan } from './pages/NewScan';
import { Reports } from './pages/Reports';
import { SearchResultsPage } from './pages/SearchResults';
import { Policies } from './pages/Policies';
import { Profile } from './pages/Profile';
import { Notifications } from './pages/Notifications';
import { Settings } from './pages/Settings';
import { Toaster } from 'sonner';
import { AuthProvider } from './auth/AuthProvider';
import { ProtectedRoute } from './auth/ProtectedRoute';
import { SessionExpiryGuard } from './auth/SessionExpiryGuard';
import { LoginPage } from './pages/access/LoginPage';
import { MfaChallengePage } from './pages/access/MfaChallengePage';
import { ChangePasswordPage } from './pages/access/ChangePasswordPage';
import { ProfileSecurityPage } from './pages/access/ProfileSecurityPage';
import { ActiveSessionsPage } from './pages/access/ActiveSessionsPage';
import { UserManagementPage } from './pages/access/UserManagementPage';
import { UserDetailsPage } from './pages/access/UserDetailsPage';
import { RoleManagementPage } from './pages/access/RoleManagementPage';
import { RoleDetailsPage } from './pages/access/RoleDetailsPage';
import { SecurityAuditPage } from './pages/access/SecurityAuditPage';
import { SecurityAuditDetailsPage } from './pages/access/SecurityAuditDetailsPage';
import { AuditIntegrityPage } from './pages/access/AuditIntegrityPage';
import { ForbiddenPage } from './pages/access/ForbiddenPage';
import { PublicLandingPage, KnownLimitationsPage } from './pages/access/PublicLandingPage';
import { SignUpPage } from './pages/access/SignUpPage';
import { AccountPendingPage } from './pages/access/AccountPendingPage';
import { AccountRejectedPage } from './pages/access/AccountRejectedPage';
import { RegistrationManagementPage } from './pages/access/RegistrationManagementPage';
import { RegistrationDetailsPage } from './pages/access/RegistrationDetailsPage';

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
const CorrelationOverview=lazy(()=>import('./pages/correlation/CorrelationOverview').then(m=>({default:m.CorrelationOverview})));const UnifiedEntityList=lazy(()=>import('./pages/correlation/UnifiedEntityList').then(m=>({default:m.UnifiedEntityList})));const UnifiedEntityDetails=lazy(()=>import('./pages/correlation/UnifiedEntityDetails').then(m=>({default:m.UnifiedEntityDetails})));const CorrelationMatchList=lazy(()=>import('./pages/correlation/CorrelationMatchList').then(m=>({default:m.CorrelationMatchList})));const CorrelationMatchDetails=lazy(()=>import('./pages/correlation/CorrelationMatchDetails').then(m=>({default:m.CorrelationMatchDetails})));const IncidentCaseList=lazy(()=>import('./pages/correlation/IncidentCaseList').then(m=>({default:m.IncidentCaseList})));const IncidentCaseDetails=lazy(()=>import('./pages/correlation/IncidentCaseDetails').then(m=>({default:m.IncidentCaseDetails})));const IncidentReports=lazy(()=>import('./pages/correlation/IncidentReports').then(m=>({default:m.IncidentReports})));const IncidentReportDetails=lazy(()=>import('./pages/correlation/IncidentReportDetails').then(m=>({default:m.IncidentReportDetails})));
const GovernanceOverview=lazy(()=>import('./pages/governance/GovernanceOverview').then(m=>({default:m.GovernanceOverview})));const RiskRegister=lazy(()=>import('./pages/governance/RiskRegister').then(m=>({default:m.RiskRegister})));const RiskDetails=lazy(()=>import('./pages/governance/RiskDetails').then(m=>({default:m.RiskDetails})));const FrameworkList=lazy(()=>import('./pages/governance/FrameworkList').then(m=>({default:m.FrameworkList})));const FrameworkDetails=lazy(()=>import('./pages/governance/FrameworkDetails').then(m=>({default:m.FrameworkDetails})));const MappingReviewQueue=lazy(()=>import('./pages/governance/MappingReviewQueue').then(m=>({default:m.MappingReviewQueue})));const TreatmentOverview=lazy(()=>import('./pages/governance/TreatmentOverview').then(m=>({default:m.TreatmentOverview})));const ExceptionRegister=lazy(()=>import('./pages/governance/ExceptionRegister').then(m=>({default:m.ExceptionRegister})));const EvidencePackageList=lazy(()=>import('./pages/governance/EvidencePackageList').then(m=>({default:m.EvidencePackageList})));const EvidencePackageDetails=lazy(()=>import('./pages/governance/EvidencePackageDetails').then(m=>({default:m.EvidencePackageDetails})));const GovernanceReviewList=lazy(()=>import('./pages/governance/GovernanceReviewList').then(m=>({default:m.GovernanceReviewList})));const GovernanceReviewDetails=lazy(()=>import('./pages/governance/GovernanceReviewDetails').then(m=>({default:m.GovernanceReviewDetails})));const GovernanceReports=lazy(()=>import('./pages/governance/GovernanceReports').then(m=>({default:m.GovernanceReports})));const GovernanceReportDetails=lazy(()=>import('./pages/governance/GovernanceReportDetails').then(m=>({default:m.GovernanceReportDetails})));
const OperationsOverviewPage=lazy(()=>import('./pages/operations/OperationsOverviewPage').then(m=>({default:m.OperationsOverviewPage})));
const HealthPage=lazy(()=>import('./pages/operations/HealthPage').then(m=>({default:m.HealthPage})));
const DiagnosticsPage=lazy(()=>import('./pages/operations/DiagnosticsPage').then(m=>({default:m.DiagnosticsPage})));
const ConfigurationStatusPage=lazy(()=>import('./pages/operations/ConfigurationStatusPage').then(m=>({default:m.ConfigurationStatusPage})));
const JobsPage=lazy(()=>import('./pages/operations/JobsPage').then(m=>({default:m.JobsPage})));
const JobDetailsPage=lazy(()=>import('./pages/operations/JobDetailsPage').then(m=>({default:m.JobDetailsPage})));
const BackupsPage=lazy(()=>import('./pages/operations/BackupsPage').then(m=>({default:m.BackupsPage})));
const BackupDetailsPage=lazy(()=>import('./pages/operations/BackupDetailsPage').then(m=>({default:m.BackupDetailsPage})));
const RestoresPage=lazy(()=>import('./pages/operations/RestoresPage').then(m=>({default:m.RestoresPage})));
const RestoreDetailsPage=lazy(()=>import('./pages/operations/RestoreDetailsPage').then(m=>({default:m.RestoreDetailsPage})));
const ExportsPage=lazy(()=>import('./pages/operations/ExportsPage').then(m=>({default:m.ExportsPage})));
const ExportDetailsPage=lazy(()=>import('./pages/operations/ExportDetailsPage').then(m=>({default:m.ExportDetailsPage})));
const RetentionPage=lazy(()=>import('./pages/operations/RetentionPage').then(m=>({default:m.RetentionPage})));
const DemoEnvironmentPage=lazy(()=>import('./pages/operations/DemoEnvironmentPage').then(m=>({default:m.DemoEnvironmentPage})));
const SoftwareInventoryPage=lazy(()=>import('./pages/operations/SoftwareInventoryPage').then(m=>({default:m.SoftwareInventoryPage})));
const ReleasesPage=lazy(()=>import('./pages/operations/ReleasesPage').then(m=>({default:m.ReleasesPage})));
const ReleaseDetailsPage=lazy(()=>import('./pages/operations/ReleaseDetailsPage').then(m=>({default:m.ReleaseDetailsPage})));

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
    <AuthProvider>
    <Router>
      <SessionExpiryGuard>
      <Routes>
        <Route path="/" element={<PublicLandingPage />} />
        <Route path="/login" element={<LoginPage />} />
        <Route path="/signup" element={<SignUpPage />} />
        <Route path="/account-pending" element={<AccountPendingPage />} />
        <Route path="/account-rejected" element={<AccountRejectedPage />} />
        <Route path="/known-limitations" element={<KnownLimitationsPage />} />
        <Route path="/mfa-challenge" element={<MfaChallengePage />} />
        <Route path="/forbidden" element={<ForbiddenPage />} />
        <Route element={<ProtectedRoute />}>
        <Route path="/change-password" element={<ChangePasswordPage />} />
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
          <Route path="/correlation" element={<Suspense fallback={<LoadingRoute/>}><CorrelationOverview/></Suspense>}/><Route path="/correlation/entities" element={<Suspense fallback={<LoadingRoute/>}><UnifiedEntityList/></Suspense>}/><Route path="/correlation/entities/:entityId" element={<Suspense fallback={<LoadingRoute/>}><UnifiedEntityDetails/></Suspense>}/><Route path="/correlation/matches" element={<Suspense fallback={<LoadingRoute/>}><CorrelationMatchList/></Suspense>}/><Route path="/correlation/matches/:matchId" element={<Suspense fallback={<LoadingRoute/>}><CorrelationMatchDetails/></Suspense>}/><Route path="/correlation/cases" element={<Suspense fallback={<LoadingRoute/>}><IncidentCaseList/></Suspense>}/><Route path="/correlation/cases/:caseId" element={<Suspense fallback={<LoadingRoute/>}><IncidentCaseDetails/></Suspense>}/><Route path="/correlation/reports" element={<Suspense fallback={<LoadingRoute/>}><IncidentReports/></Suspense>}/><Route path="/correlation/reports/:reportId" element={<Suspense fallback={<LoadingRoute/>}><IncidentReportDetails/></Suspense>}/>
          <Route path="/governance" element={<Suspense fallback={<LoadingRoute/>}><GovernanceOverview/></Suspense>}/><Route path="/governance/risks" element={<Suspense fallback={<LoadingRoute/>}><RiskRegister/></Suspense>}/><Route path="/governance/risks/:riskId" element={<Suspense fallback={<LoadingRoute/>}><RiskDetails/></Suspense>}/><Route path="/governance/frameworks" element={<Suspense fallback={<LoadingRoute/>}><FrameworkList/></Suspense>}/><Route path="/governance/frameworks/:frameworkId" element={<Suspense fallback={<LoadingRoute/>}><FrameworkDetails/></Suspense>}/><Route path="/governance/mappings" element={<Suspense fallback={<LoadingRoute/>}><MappingReviewQueue/></Suspense>}/><Route path="/governance/treatments" element={<Suspense fallback={<LoadingRoute/>}><TreatmentOverview/></Suspense>}/><Route path="/governance/exceptions" element={<Suspense fallback={<LoadingRoute/>}><ExceptionRegister/></Suspense>}/><Route path="/governance/evidence" element={<Suspense fallback={<LoadingRoute/>}><EvidencePackageList/></Suspense>}/><Route path="/governance/evidence/:packageId" element={<Suspense fallback={<LoadingRoute/>}><EvidencePackageDetails/></Suspense>}/><Route path="/governance/reviews" element={<Suspense fallback={<LoadingRoute/>}><GovernanceReviewList/></Suspense>}/><Route path="/governance/reviews/:reviewId" element={<Suspense fallback={<LoadingRoute/>}><GovernanceReviewDetails/></Suspense>}/><Route path="/governance/reports" element={<Suspense fallback={<LoadingRoute/>}><GovernanceReports/></Suspense>}/><Route path="/governance/reports/:reportId" element={<Suspense fallback={<LoadingRoute/>}><GovernanceReportDetails/></Suspense>}/>
          <Route path="/operations" element={<Suspense fallback={<LoadingRoute/>}><OperationsOverviewPage/></Suspense>}/>
          <Route path="/operations/health" element={<Suspense fallback={<LoadingRoute/>}><HealthPage/></Suspense>}/>
          <Route path="/operations/diagnostics" element={<Suspense fallback={<LoadingRoute/>}><DiagnosticsPage/></Suspense>}/>
          <Route path="/operations/configuration" element={<Suspense fallback={<LoadingRoute/>}><ConfigurationStatusPage/></Suspense>}/>
          <Route path="/operations/jobs" element={<Suspense fallback={<LoadingRoute/>}><JobsPage/></Suspense>}/>
          <Route path="/operations/jobs/:jobId" element={<Suspense fallback={<LoadingRoute/>}><JobDetailsPage/></Suspense>}/>
          <Route path="/operations/backups" element={<Suspense fallback={<LoadingRoute/>}><BackupsPage/></Suspense>}/>
          <Route path="/operations/backups/:backupId" element={<Suspense fallback={<LoadingRoute/>}><BackupDetailsPage/></Suspense>}/>
          <Route path="/operations/restores" element={<Suspense fallback={<LoadingRoute/>}><RestoresPage/></Suspense>}/>
          <Route path="/operations/restores/:restoreId" element={<Suspense fallback={<LoadingRoute/>}><RestoreDetailsPage/></Suspense>}/>
          <Route path="/operations/exports" element={<Suspense fallback={<LoadingRoute/>}><ExportsPage/></Suspense>}/>
          <Route path="/operations/exports/:exportId" element={<Suspense fallback={<LoadingRoute/>}><ExportDetailsPage/></Suspense>}/>
          <Route path="/operations/retention" element={<Suspense fallback={<LoadingRoute/>}><RetentionPage/></Suspense>}/>
          <Route path="/operations/demo" element={<Suspense fallback={<LoadingRoute/>}><DemoEnvironmentPage/></Suspense>}/>
          <Route path="/operations/inventory" element={<Suspense fallback={<LoadingRoute/>}><SoftwareInventoryPage/></Suspense>}/>
          <Route path="/operations/releases" element={<Suspense fallback={<LoadingRoute/>}><ReleasesPage/></Suspense>}/>
          <Route path="/operations/releases/:releaseId" element={<Suspense fallback={<LoadingRoute/>}><ReleaseDetailsPage/></Suspense>}/>
          <Route path="/reports" element={<Reports />} />
          <Route path="/policies" element={<Policies />} />
          <Route path="/search" element={<SearchResultsPage />} />
          <Route path="/profile" element={<Profile />} />
          <Route path="/profile/security" element={<ProfileSecurityPage />} />
          <Route path="/profile/sessions" element={<ActiveSessionsPage />} />
          <Route path="/notifications" element={<Notifications />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="/admin/users" element={<UserManagementPage />} />
          <Route path="/admin/registrations" element={<RegistrationManagementPage />} />
          <Route path="/admin/registrations/:userId" element={<RegistrationDetailsPage />} />
          <Route path="/admin/users/:userId" element={<UserDetailsPage />} />
          <Route path="/admin/roles" element={<RoleManagementPage />} />
          <Route path="/admin/roles/:roleId" element={<RoleDetailsPage />} />
          <Route path="/security-audit" element={<SecurityAuditPage />} />
          <Route path="/security-audit/integrity" element={<AuditIntegrityPage />} />
          <Route path="/security-audit/:eventId" element={<SecurityAuditDetailsPage />} />
        </Route>
        </Route>
      </Routes>
      <Toaster theme="dark" position="bottom-right" />
      </SessionExpiryGuard>
    </Router>
    </AuthProvider>
  );
}

export default App;
