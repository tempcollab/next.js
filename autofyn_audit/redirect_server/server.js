'use strict'

const http = require('http')

// Minimal valid 1x1 JFIF JPEG (FF D8 FF bytes at start)
const JPEG_BASE64 =
  '/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0a' +
  'HBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIy' +
  'MjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wAARCAABAAEDASIAAhEB' +
  'AxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAFRABAAAAAAAAAAAAAAAAAAAACf/' +
  'EABQBAQAAAAAAAAAAAAAAAAAAAAD/xAAUEQEAAAAAAAAAAAAAAAAAAAAA/9oADAMBAAIRAxEAPwCwAB//2Q=='

const JPEG_BYTES = Buffer.from(JPEG_BASE64, 'base64')

const PORT = 8080

const server = http.createServer((req, res) => {
  if (req.method === 'GET' && req.url === '/redirect-to-secret') {
    res.writeHead(302, {
      Location: 'http://audit-secret-server:9090/secret-image.jpg',
    })
    res.end()
    return
  }

  if (req.method === 'GET' && req.url === '/legitimate.jpg') {
    res.writeHead(200, {
      'Content-Type': 'image/jpeg',
      'Content-Length': JPEG_BYTES.length,
    })
    res.end(JPEG_BYTES)
    return
  }

  res.writeHead(404, { 'Content-Type': 'text/plain' })
  res.end('Not Found')
})

server.listen(PORT, () => {
  process.stdout.write(`Redirect server listening on port ${PORT}\n`)
})
