'use server'

export async function processData(formData: FormData): Promise<void> {
  const body = formData.get('data') as string
  console.log(`Received ${body?.length ?? 0} bytes`)
}
