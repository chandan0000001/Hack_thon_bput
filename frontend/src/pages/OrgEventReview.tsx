/**
 * ORG-DASHBOARD-P1 stub — the event review page itself lands in
 * ORG-DASHBOARD-P2. Exists so the dashboard's [Review] navigation has a
 * real destination with the event id in the URL.
 */

import { useParams } from 'react-router-dom';

export default function OrgEventReview() {
  const { eventId } = useParams<{ eventId: string }>();
  return (
    <div className="p-6" data-testid="event-review-stub">
      <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-6 space-y-2">
        <div className="text-sm text-zinc-300">Event review</div>
        <div className="text-xs text-zinc-500">
          Review workflow for event <span className="text-zinc-300">{eventId}</span> arrives in
          ORG-DASHBOARD-P2.
        </div>
      </div>
    </div>
  );
}
