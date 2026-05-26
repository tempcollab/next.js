export const runtime = 'edge'

import { processData } from './actions'

export default function HomePage() {
  return (
    <main>
      <h1>Edge Runtime Audit Page</h1>
      <form action={processData}>
        <input type="hidden" name="data" value="test" />
        <button type="submit">Submit</button>
      </form>
    </main>
  )
}
