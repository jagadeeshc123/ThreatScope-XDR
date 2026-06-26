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

function Layout() {
  return (
    <div className="flex h-screen bg-background text-foreground overflow-hidden">
      <Sidebar />
      <div className="flex-1 flex flex-col h-screen overflow-hidden">
        <Topbar />
        <main className="flex-1 overflow-auto">
          <Outlet />
        </main>
      </div>
    </div>
  );
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
