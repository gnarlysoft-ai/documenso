import { redirect } from 'react-router';

import { getOptionalSession } from '@documenso/auth/server/lib/utils/get-session';
import { isAdmin } from '@documenso/lib/utils/is-admin';

/**
 * Every admin route loader must call this before it loads any data.
 *
 * A data request can ask React Router to run one route's loader without the
 * loaders of its parent layouts, so the check in `admin+/_layout.tsx` does not
 * protect the child routes on its own. Upstream solved the same problem with
 * route middleware (documenso/documenso#3351).
 */
export const requireAdmin = async (request: Request) => {
  const { user } = await getOptionalSession(request);

  if (!user || !isAdmin(user)) {
    throw redirect('/');
  }

  return user;
};
