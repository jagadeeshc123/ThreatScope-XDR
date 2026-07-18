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
import { IntegrationsOverviewPage, ConnectorCatalogPage, ConnectorsPage, ConnectorCreatePage, ConnectorDetailsPage, ConnectorEditPage, ConnectorTestPage, ConnectorCredentialsPage, ConnectorNetworkPolicyPage, SubscriptionsPage, SubscriptionDetailsPage, MappingsPage, MappingEditorPage, OutboxPage, DeliveriesPage, DeliveryDetailsPage, DeadLettersPage, DeadLetterDetailsPage, InboundEndpointsPage, InboundEndpointDetailsPage, InboundEventsPage, InboundEventDetailsPage, HealthChecksPage, ExternalReferencesPage, IntegrationReportsPage, IntegrationReportDetailsPage } from './pages/integrations/IntegrationsPages';

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
const ThreatIntelOverviewPage=lazy(()=>import('./pages/threat-intelligence/ThreatIntelOverviewPage').then(m=>({default:m.ThreatIntelOverviewPage})));const IndicatorsPage=lazy(()=>import('./pages/threat-intelligence/IndicatorsPage').then(m=>({default:m.IndicatorsPage})));const IndicatorDetailsPage=lazy(()=>import('./pages/threat-intelligence/IndicatorDetailsPage').then(m=>({default:m.IndicatorDetailsPage})));const AddIndicatorPage=lazy(()=>import('./pages/threat-intelligence/AddIndicatorPage').then(m=>({default:m.AddIndicatorPage})));const SourcesPage=lazy(()=>import('./pages/threat-intelligence/SourcesPage').then(m=>({default:m.SourcesPage})));const ImportsPage=lazy(()=>import('./pages/threat-intelligence/ImportsPage').then(m=>({default:m.ImportsPage})));const ImportDetailsPage=lazy(()=>import('./pages/threat-intelligence/ImportDetailsPage').then(m=>({default:m.ImportDetailsPage})));const WatchlistsPage=lazy(()=>import('./pages/threat-intelligence/WatchlistsPage').then(m=>({default:m.WatchlistsPage})));const WatchlistDetailsPage=lazy(()=>import('./pages/threat-intelligence/WatchlistDetailsPage').then(m=>({default:m.WatchlistDetailsPage})));const CampaignsPage=lazy(()=>import('./pages/threat-intelligence/CampaignsPage').then(m=>({default:m.CampaignsPage})));const CampaignDetailsPage=lazy(()=>import('./pages/threat-intelligence/CampaignDetailsPage').then(m=>({default:m.CampaignDetailsPage})));const SightingsPage=lazy(()=>import('./pages/threat-intelligence/SightingsPage').then(m=>({default:m.SightingsPage})));const MatchesPage=lazy(()=>import('./pages/threat-intelligence/MatchesPage').then(m=>({default:m.MatchesPage})));const MatchDetailsPage=lazy(()=>import('./pages/threat-intelligence/MatchDetailsPage').then(m=>({default:m.MatchDetailsPage})));const ThreatIntelReportsPage=lazy(()=>import('./pages/threat-intelligence/ThreatIntelReportsPage').then(m=>({default:m.ThreatIntelReportsPage})));const ThreatIntelReportDetailsPage=lazy(()=>import('./pages/threat-intelligence/ThreatIntelReportDetailsPage').then(m=>({default:m.ThreatIntelReportDetailsPage})));
const DetectionOverviewPage=lazy(()=>import('./pages/detections/DetectionOverviewPage').then(m=>({default:m.DetectionOverviewPage})));const DetectionRulesPage=lazy(()=>import('./pages/detections/DetectionRulesPage').then(m=>({default:m.DetectionRulesPage})));const DetectionRuleDetailsPage=lazy(()=>import('./pages/detections/DetectionRuleDetailsPage').then(m=>({default:m.DetectionRuleDetailsPage})));const DetectionRuleEditorPage=lazy(()=>import('./pages/detections/DetectionRuleEditorPage').then(m=>({default:m.DetectionRuleEditorPage})));const DetectionImportPage=lazy(()=>import('./pages/detections/DetectionImportPage').then(m=>({default:m.DetectionImportPage})));const DetectionPacksPage=lazy(()=>import('./pages/detections/DetectionPacksPage').then(m=>({default:m.DetectionPacksPage})));const DetectionPackDetailsPage=lazy(()=>import('./pages/detections/DetectionPackDetailsPage').then(m=>({default:m.DetectionPackDetailsPage})));const AttackCoveragePage=lazy(()=>import('./pages/detections/AttackCoveragePage').then(m=>({default:m.AttackCoveragePage})));const DetectionExecutionsPage=lazy(()=>import('./pages/detections/DetectionExecutionsPage').then(m=>({default:m.DetectionExecutionsPage})));const DetectionExecutionDetailsPage=lazy(()=>import('./pages/detections/DetectionExecutionDetailsPage').then(m=>({default:m.DetectionExecutionDetailsPage})));const DetectionMatchesPage=lazy(()=>import('./pages/detections/DetectionMatchesPage').then(m=>({default:m.DetectionMatchesPage})));const DetectionMatchDetailsPage=lazy(()=>import('./pages/detections/DetectionMatchDetailsPage').then(m=>({default:m.DetectionMatchDetailsPage})));const DetectionSuppressionsPage=lazy(()=>import('./pages/detections/DetectionSuppressionsPage').then(m=>({default:m.DetectionSuppressionsPage})));const DetectionReportsPage=lazy(()=>import('./pages/detections/DetectionReportsPage').then(m=>({default:m.DetectionReportsPage})));const DetectionReportDetailsPage=lazy(()=>import('./pages/detections/DetectionReportDetailsPage').then(m=>({default:m.DetectionReportDetailsPage})));
const VulnerabilityOverviewPage=lazy(()=>import('./pages/vulnerability-management/VulnerabilityOverviewPage').then(m=>({default:m.VulnerabilityOverviewPage})));const AssetInventoryPage=lazy(()=>import('./pages/vulnerability-management/AssetInventoryPage').then(m=>({default:m.AssetInventoryPage})));const AssetDetailsPage=lazy(()=>import('./pages/vulnerability-management/AssetDetailsPage').then(m=>({default:m.AssetDetailsPage})));const VulnerabilitiesPage=lazy(()=>import('./pages/vulnerability-management/VulnerabilitiesPage').then(m=>({default:m.VulnerabilitiesPage})));const VulnerabilityDetailsPage=lazy(()=>import('./pages/vulnerability-management/VulnerabilityDetailsPage').then(m=>({default:m.VulnerabilityDetailsPage})));const RemediationPlansPage=lazy(()=>import('./pages/vulnerability-management/RemediationPlansPage').then(m=>({default:m.RemediationPlansPage})));const RemediationPlanDetailsPage=lazy(()=>import('./pages/vulnerability-management/RemediationPlanDetailsPage').then(m=>({default:m.RemediationPlanDetailsPage})));const SlaDashboardPage=lazy(()=>import('./pages/vulnerability-management/SlaDashboardPage').then(m=>({default:m.SlaDashboardPage})));const RiskAcceptancesPage=lazy(()=>import('./pages/vulnerability-management/RiskAcceptancesPage').then(m=>({default:m.RiskAcceptancesPage})));const VerificationQueuePage=lazy(()=>import('./pages/vulnerability-management/VerificationQueuePage').then(m=>({default:m.VerificationQueuePage})));const RemediationLibraryPage=lazy(()=>import('./pages/vulnerability-management/RemediationLibraryPage').then(m=>({default:m.RemediationLibraryPage})));const VulnerabilityReportsPage=lazy(()=>import('./pages/vulnerability-management/VulnerabilityReportsPage').then(m=>({default:m.VulnerabilityReportsPage})));const VulnerabilityReportDetailsPage=lazy(()=>import('./pages/vulnerability-management/VulnerabilityReportDetailsPage').then(m=>({default:m.VulnerabilityReportDetailsPage})));
const SoarOverviewPage=lazy(()=>import('./pages/soar/SoarOverviewPage').then(m=>({default:m.SoarOverviewPage})));const PlaybooksPage=lazy(()=>import('./pages/soar/PlaybooksPage').then(m=>({default:m.PlaybooksPage})));const PlaybookDetailsPage=lazy(()=>import('./pages/soar/PlaybookDetailsPage').then(m=>({default:m.PlaybookDetailsPage})));const PlaybookEditorPage=lazy(()=>import('./pages/soar/PlaybookEditorPage').then(m=>({default:m.PlaybookEditorPage})));const PlaybookVersionsPage=lazy(()=>import('./pages/soar/PlaybookVersionsPage').then(m=>({default:m.PlaybookVersionsPage})));const PlaybookVersionComparePage=lazy(()=>import('./pages/soar/PlaybookVersionComparePage').then(m=>({default:m.PlaybookVersionComparePage})));const PlaybookTemplatesPage=lazy(()=>import('./pages/soar/PlaybookTemplatesPage').then(m=>({default:m.PlaybookTemplatesPage})));const TriggerRulesPage=lazy(()=>import('./pages/soar/TriggerRulesPage').then(m=>({default:m.TriggerRulesPage})));const TriggerRuleDetailsPage=lazy(()=>import('./pages/soar/TriggerRuleDetailsPage').then(m=>({default:m.TriggerRuleDetailsPage})));const ExecutionsPage=lazy(()=>import('./pages/soar/ExecutionsPage').then(m=>({default:m.ExecutionsPage})));const ExecutionDetailsPage=lazy(()=>import('./pages/soar/ExecutionDetailsPage').then(m=>({default:m.ExecutionDetailsPage})));const ApprovalsPage=lazy(()=>import('./pages/soar/ApprovalsPage').then(m=>({default:m.ApprovalsPage})));const ApprovalDetailsPage=lazy(()=>import('./pages/soar/ApprovalDetailsPage').then(m=>({default:m.ApprovalDetailsPage})));const AnalystInputsPage=lazy(()=>import('./pages/soar/AnalystInputsPage').then(m=>({default:m.AnalystInputsPage})));const ActionCatalogPage=lazy(()=>import('./pages/soar/ActionCatalogPage').then(m=>({default:m.ActionCatalogPage})));const ActionPoliciesPage=lazy(()=>import('./pages/soar/ActionPoliciesPage').then(m=>({default:m.ActionPoliciesPage})));const RollbacksPage=lazy(()=>import('./pages/soar/RollbacksPage').then(m=>({default:m.RollbacksPage})));const RollbackDetailsPage=lazy(()=>import('./pages/soar/RollbackDetailsPage').then(m=>({default:m.RollbackDetailsPage})));const SoarReportsPage=lazy(()=>import('./pages/soar/SoarReportsPage').then(m=>({default:m.SoarReportsPage})));const SoarReportDetailsPage=lazy(()=>import('./pages/soar/SoarReportDetailsPage').then(m=>({default:m.SoarReportDetailsPage})));
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
          <Route path="/threat-intelligence" element={<Suspense fallback={<LoadingRoute/>}><ThreatIntelOverviewPage/></Suspense>}/><Route path="/threat-intelligence/indicators" element={<Suspense fallback={<LoadingRoute/>}><IndicatorsPage/></Suspense>}/><Route path="/threat-intelligence/indicators/new" element={<Suspense fallback={<LoadingRoute/>}><AddIndicatorPage/></Suspense>}/><Route path="/threat-intelligence/indicators/:indicatorId" element={<Suspense fallback={<LoadingRoute/>}><IndicatorDetailsPage/></Suspense>}/><Route path="/threat-intelligence/sources" element={<Suspense fallback={<LoadingRoute/>}><SourcesPage/></Suspense>}/><Route path="/threat-intelligence/imports" element={<Suspense fallback={<LoadingRoute/>}><ImportsPage/></Suspense>}/><Route path="/threat-intelligence/imports/:importId" element={<Suspense fallback={<LoadingRoute/>}><ImportDetailsPage/></Suspense>}/><Route path="/threat-intelligence/watchlists" element={<Suspense fallback={<LoadingRoute/>}><WatchlistsPage/></Suspense>}/><Route path="/threat-intelligence/watchlists/:watchlistId" element={<Suspense fallback={<LoadingRoute/>}><WatchlistDetailsPage/></Suspense>}/><Route path="/threat-intelligence/campaigns" element={<Suspense fallback={<LoadingRoute/>}><CampaignsPage/></Suspense>}/><Route path="/threat-intelligence/campaigns/:campaignId" element={<Suspense fallback={<LoadingRoute/>}><CampaignDetailsPage/></Suspense>}/><Route path="/threat-intelligence/sightings" element={<Suspense fallback={<LoadingRoute/>}><SightingsPage/></Suspense>}/><Route path="/threat-intelligence/matches" element={<Suspense fallback={<LoadingRoute/>}><MatchesPage/></Suspense>}/><Route path="/threat-intelligence/matches/:matchId" element={<Suspense fallback={<LoadingRoute/>}><MatchDetailsPage/></Suspense>}/><Route path="/threat-intelligence/reports" element={<Suspense fallback={<LoadingRoute/>}><ThreatIntelReportsPage/></Suspense>}/><Route path="/threat-intelligence/reports/:reportId" element={<Suspense fallback={<LoadingRoute/>}><ThreatIntelReportDetailsPage/></Suspense>}/>
          <Route path="/detections" element={<Suspense fallback={<LoadingRoute/>}><DetectionOverviewPage/></Suspense>}/><Route path="/detections/rules" element={<Suspense fallback={<LoadingRoute/>}><DetectionRulesPage/></Suspense>}/><Route path="/detections/rules/new" element={<Suspense fallback={<LoadingRoute/>}><DetectionRuleEditorPage/></Suspense>}/><Route path="/detections/rules/:ruleId" element={<Suspense fallback={<LoadingRoute/>}><DetectionRuleDetailsPage/></Suspense>}/><Route path="/detections/rules/:ruleId/edit" element={<Suspense fallback={<LoadingRoute/>}><DetectionRuleEditorPage/></Suspense>}/><Route path="/detections/import" element={<Suspense fallback={<LoadingRoute/>}><DetectionImportPage/></Suspense>}/><Route path="/detections/packs" element={<Suspense fallback={<LoadingRoute/>}><DetectionPacksPage/></Suspense>}/><Route path="/detections/packs/:packId" element={<Suspense fallback={<LoadingRoute/>}><DetectionPackDetailsPage/></Suspense>}/><Route path="/detections/coverage" element={<Suspense fallback={<LoadingRoute/>}><AttackCoveragePage/></Suspense>}/><Route path="/detections/executions" element={<Suspense fallback={<LoadingRoute/>}><DetectionExecutionsPage/></Suspense>}/><Route path="/detections/executions/:executionId" element={<Suspense fallback={<LoadingRoute/>}><DetectionExecutionDetailsPage/></Suspense>}/><Route path="/detections/matches" element={<Suspense fallback={<LoadingRoute/>}><DetectionMatchesPage/></Suspense>}/><Route path="/detections/matches/:matchId" element={<Suspense fallback={<LoadingRoute/>}><DetectionMatchDetailsPage/></Suspense>}/><Route path="/detections/suppressions" element={<Suspense fallback={<LoadingRoute/>}><DetectionSuppressionsPage/></Suspense>}/><Route path="/detections/reports" element={<Suspense fallback={<LoadingRoute/>}><DetectionReportsPage/></Suspense>}/><Route path="/detections/reports/:reportId" element={<Suspense fallback={<LoadingRoute/>}><DetectionReportDetailsPage/></Suspense>}/>
          <Route path="/vulnerability-management" element={<Suspense fallback={<LoadingRoute/>}><VulnerabilityOverviewPage/></Suspense>}/><Route path="/vulnerability-management/assets" element={<Suspense fallback={<LoadingRoute/>}><AssetInventoryPage/></Suspense>}/><Route path="/vulnerability-management/assets/:assetId" element={<Suspense fallback={<LoadingRoute/>}><AssetDetailsPage/></Suspense>}/><Route path="/vulnerability-management/vulnerabilities" element={<Suspense fallback={<LoadingRoute/>}><VulnerabilitiesPage/></Suspense>}/><Route path="/vulnerability-management/vulnerabilities/:vulnerabilityId" element={<Suspense fallback={<LoadingRoute/>}><VulnerabilityDetailsPage/></Suspense>}/><Route path="/vulnerability-management/plans" element={<Suspense fallback={<LoadingRoute/>}><RemediationPlansPage/></Suspense>}/><Route path="/vulnerability-management/plans/:planId" element={<Suspense fallback={<LoadingRoute/>}><RemediationPlanDetailsPage/></Suspense>}/><Route path="/vulnerability-management/sla" element={<Suspense fallback={<LoadingRoute/>}><SlaDashboardPage/></Suspense>}/><Route path="/vulnerability-management/risk-acceptances" element={<Suspense fallback={<LoadingRoute/>}><RiskAcceptancesPage/></Suspense>}/><Route path="/vulnerability-management/verifications" element={<Suspense fallback={<LoadingRoute/>}><VerificationQueuePage/></Suspense>}/><Route path="/vulnerability-management/library" element={<Suspense fallback={<LoadingRoute/>}><RemediationLibraryPage/></Suspense>}/><Route path="/vulnerability-management/reports" element={<Suspense fallback={<LoadingRoute/>}><VulnerabilityReportsPage/></Suspense>}/><Route path="/vulnerability-management/reports/:reportId" element={<Suspense fallback={<LoadingRoute/>}><VulnerabilityReportDetailsPage/></Suspense>}/>
          <Route path="/soar" element={<Suspense fallback={<LoadingRoute/>}><SoarOverviewPage/></Suspense>}/><Route path="/soar/playbooks" element={<Suspense fallback={<LoadingRoute/>}><PlaybooksPage/></Suspense>}/><Route path="/soar/playbooks/new" element={<Suspense fallback={<LoadingRoute/>}><PlaybookEditorPage/></Suspense>}/><Route path="/soar/playbooks/:playbookId" element={<Suspense fallback={<LoadingRoute/>}><PlaybookDetailsPage/></Suspense>}/><Route path="/soar/playbooks/:playbookId/edit" element={<Suspense fallback={<LoadingRoute/>}><PlaybookEditorPage/></Suspense>}/><Route path="/soar/playbooks/:playbookId/versions" element={<Suspense fallback={<LoadingRoute/>}><PlaybookVersionsPage/></Suspense>}/><Route path="/soar/playbooks/:playbookId/versions/compare" element={<Suspense fallback={<LoadingRoute/>}><PlaybookVersionComparePage/></Suspense>}/><Route path="/soar/templates" element={<Suspense fallback={<LoadingRoute/>}><PlaybookTemplatesPage/></Suspense>}/><Route path="/soar/triggers" element={<Suspense fallback={<LoadingRoute/>}><TriggerRulesPage/></Suspense>}/><Route path="/soar/triggers/:triggerId" element={<Suspense fallback={<LoadingRoute/>}><TriggerRuleDetailsPage/></Suspense>}/><Route path="/soar/executions" element={<Suspense fallback={<LoadingRoute/>}><ExecutionsPage/></Suspense>}/><Route path="/soar/executions/:executionId" element={<Suspense fallback={<LoadingRoute/>}><ExecutionDetailsPage/></Suspense>}/><Route path="/soar/approvals" element={<Suspense fallback={<LoadingRoute/>}><ApprovalsPage/></Suspense>}/><Route path="/soar/approvals/:approvalId" element={<Suspense fallback={<LoadingRoute/>}><ApprovalDetailsPage/></Suspense>}/><Route path="/soar/analyst-inputs" element={<Suspense fallback={<LoadingRoute/>}><AnalystInputsPage/></Suspense>}/><Route path="/soar/actions" element={<Suspense fallback={<LoadingRoute/>}><ActionCatalogPage/></Suspense>}/><Route path="/soar/action-policies" element={<Suspense fallback={<LoadingRoute/>}><ActionPoliciesPage/></Suspense>}/><Route path="/soar/rollbacks" element={<Suspense fallback={<LoadingRoute/>}><RollbacksPage/></Suspense>}/><Route path="/soar/rollbacks/:rollbackId" element={<Suspense fallback={<LoadingRoute/>}><RollbackDetailsPage/></Suspense>}/><Route path="/soar/reports" element={<Suspense fallback={<LoadingRoute/>}><SoarReportsPage/></Suspense>}/><Route path="/soar/reports/:reportId" element={<Suspense fallback={<LoadingRoute/>}><SoarReportDetailsPage/></Suspense>}/>
          <Route path="/integrations" element={<IntegrationsOverviewPage/>}/>
          <Route path="/integrations/catalog" element={<ConnectorCatalogPage/>}/>
          <Route path="/integrations/connectors" element={<ConnectorsPage/>}/>
          <Route path="/integrations/connectors/new" element={<ConnectorCreatePage/>}/>
          <Route path="/integrations/connectors/:connectorId" element={<ConnectorDetailsPage/>}/>
          <Route path="/integrations/connectors/:connectorId/edit" element={<ConnectorEditPage/>}/>
          <Route path="/integrations/connectors/:connectorId/test" element={<ConnectorTestPage/>}/>
          <Route path="/integrations/connectors/:connectorId/credentials" element={<ConnectorCredentialsPage/>}/>
          <Route path="/integrations/connectors/:connectorId/network-policy" element={<ConnectorNetworkPolicyPage/>}/>
          <Route path="/integrations/subscriptions" element={<SubscriptionsPage/>}/>
          <Route path="/integrations/subscriptions/:subscriptionId" element={<SubscriptionDetailsPage/>}/>
          <Route path="/integrations/mappings" element={<MappingsPage/>}/>
          <Route path="/integrations/mappings/new" element={<MappingEditorPage/>}/>
          <Route path="/integrations/mappings/:mappingId" element={<MappingEditorPage/>}/>
          <Route path="/integrations/outbox" element={<OutboxPage/>}/>
          <Route path="/integrations/deliveries" element={<DeliveriesPage/>}/>
          <Route path="/integrations/deliveries/:deliveryId" element={<DeliveryDetailsPage/>}/>
          <Route path="/integrations/dead-letters" element={<DeadLettersPage/>}/>
          <Route path="/integrations/dead-letters/:deadLetterId" element={<DeadLetterDetailsPage/>}/>
          <Route path="/integrations/inbound-endpoints" element={<InboundEndpointsPage/>}/>
          <Route path="/integrations/inbound-endpoints/:endpointId" element={<InboundEndpointDetailsPage/>}/>
          <Route path="/integrations/inbound-events" element={<InboundEventsPage/>}/>
          <Route path="/integrations/inbound-events/:eventId" element={<InboundEventDetailsPage/>}/>
          <Route path="/integrations/health" element={<HealthChecksPage/>}/>
          <Route path="/integrations/external-references" element={<ExternalReferencesPage/>}/>
          <Route path="/integrations/reports" element={<IntegrationReportsPage/>}/>
          <Route path="/integrations/reports/:reportId" element={<IntegrationReportDetailsPage/>}/>
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
