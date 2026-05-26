import { sensitiveAction } from './actions'

export default function HomePage() {
  return (
    <main>
      <h1>Audit Test Page</h1>
      <form action={sensitiveAction}>
        <button type="submit">Execute Sensitive Action</button>
      </form>
    </main>
  )
}
