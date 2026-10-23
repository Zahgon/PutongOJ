import { resolve } from 'node:path'
import test from 'ava'
import { agent } from '../../e2e.ts'

const request = agent()

const filepath = resolve(import.meta.dirname, '../utils.e2e-spec.ts')

test('Visitor cannot upload a file', async (t) => {
  const res = await request
    .post('/api/upload')
    .attach('image', filepath)

  t.is(res.status, 200)
  t.is(res.body.success, false)
  t.is(res.body.code, 401)
})

test('Visitor cannot list files', async (t) => {
  const res = await request
    .get('/api/files')

  t.is(res.status, 200)
  t.is(res.body.success, false)
  t.is(res.body.code, 401)
})

test('Visitor cannot delete a file', async (t) => {
  const res = await request
    .delete('/api/files/nonexistent-key')

  t.is(res.status, 200)
  t.is(res.body.success, false)
  t.is(res.body.code, 401)
})
