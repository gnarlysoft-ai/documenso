import { redirect } from 'react-router';

import { requireAdmin } from '~/utils/require-admin.server';

import type { Route } from './+types/_index';

export async function loader({ request }: Route.LoaderArgs) {
  await requireAdmin(request);

  throw redirect('/admin/stats');
}

export default function AdminPage() {
  // Redirect page.
}
