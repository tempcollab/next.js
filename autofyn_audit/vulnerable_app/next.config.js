/** @type {import('next').NextConfig} */
const nextConfig = {
  images: {
    remotePatterns: [
      {
        protocol: 'http',
        hostname: 'audit-redirect-server',
        port: '8080',
      },
    ],
    // Required for Docker inter-container networking (private IPs).
    // The vulnerability demonstrated is remotePatterns bypass via redirect,
    // not private IP access. In production, redirect targets would be public IPs.
    dangerouslyAllowLocalIP: true,
  },
}

module.exports = nextConfig
