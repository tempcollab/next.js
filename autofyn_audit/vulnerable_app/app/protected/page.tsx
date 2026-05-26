import { cookies } from 'next/headers'

export default async function ProtectedPage() {
  const cookieStore = await cookies()
  const session = cookieStore.get('session')?.value

  if (session === 'admin_session_token') {
    return <div id="secret">ADMIN_SECRET_DATA: launch_codes_42</div>
  }

  return <div id="denied">Access Denied</div>
}
