import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

export function middleware(request: NextRequest) {
  const backend = request.nextUrl.searchParams.get('backend')
  if (backend) {
    return NextResponse.rewrite(new URL(backend))
  }
  return NextResponse.next()
}

export const config = {
  matcher: '/',
}
