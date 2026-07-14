import { Link } from 'react-router-dom';
import { AccessDeniedNotice } from './components/AccessDeniedNotice';
export function ForbiddenPage(){return <main className="grid min-h-screen place-items-center bg-background p-5"><div className="max-w-lg"><AccessDeniedNotice/><Link to="/dashboard" className="mt-4 block text-center text-sm text-primary">Return to dashboard</Link></div></main>}
