import { Navigate } from 'react-router-dom';
import type { ReactNode } from 'react';
import { Loader2 } from 'lucide-react';
import { useAuthStore } from '../../store/authStore';

export default function ProtectedRoute({ children }: { children: ReactNode }) {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
  const hydrated = useAuthStore((s) => s.hydrated);

  const user = useAuthStore((s) => s.user);

  // Wait for session restoration (Supabase getSession) before deciding.
  if (!hydrated) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-950">
        <Loader2 className="h-6 w-6 animate-spin text-cyan-400" />
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  // F4: Org accounts are restricted to the organization window
  if (user?.account_type === 'org') {
    return <Navigate to="/org/select" replace />;
  }

  return <>{children}</>;
}
