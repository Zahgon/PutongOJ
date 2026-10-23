import test from 'ava'
import { agent } from '../../e2e.ts'
import { problemSeeds } from '../../seeds/problem.ts'

const request = agent()

test('Problem list', async (t) => {
  const res = await request
    .get('/api/problem')

  t.is(res.status, 200)
  t.true(res.body.success)
  t.truthy(Array.isArray(res.body.data.list.docs))
  t.truthy(Array.isArray(res.body.data.solved))

  if (res.body.data.list.docs.length > 0) {
    t.truthy(res.body.data.list.docs[0].title)
    t.truthy(res.body.data.list.docs[0].pid)
  }
})

test('Problem find one', async (t) => {
  const res = await request
    .get('/api/problem/1001')

  t.is(res.status, 200)

  const n = problemSeeds.find(item => item.title === res.body.data.title)!

  for (const [ key, value ] of Object.entries(n)) {
    t.deepEqual(res.body.data[key], value)
  }
})

test('Problem should fail to find one', async (t) => {
  const res = await request
    .get('/api/problem/10000')

  t.is(res.status, 200)
  t.is(res.body.success, false)
  t.is(res.body.code, 404)
})

test('Pid is not a number', async (t) => {
  const res = await request
    .get('/api/problem/xx')

  t.is(res.status, 200)
  t.is(res.body.success, false)
  t.is(res.body.code, 404)
})
