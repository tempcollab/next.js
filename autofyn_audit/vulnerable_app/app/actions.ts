'use server'

import { cookies } from 'next/headers'

export async function sensitiveAction(_formData: FormData): Promise<void> {
  const cookieStore = await cookies()
  const session = cookieStore.get('session')?.value || 'anonymous'
  console.log(`Action executed by: ${session}`)
}
