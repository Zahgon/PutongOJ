// Resets the store the e2e suite runs on (PTOJ_MONGODB_URL, PTOJ_REDIS_URL) and seeds it; run it before the server
// starts: node test/seed.ts (pretest). With --clean it only empties the store (posttest).
import { Buffer } from 'node:buffer'
import { randomUUID } from 'node:crypto'
import process from 'node:process'
import { md5, sha1 } from '@noble/hashes/legacy.js'
import { Comment, Course, disconnectMongoose, Discussion, Group, ID, Problem, Solution, User } from '@putong-oj/db'
import { Redis } from 'ioredis'
import { redisURL } from './e2e.ts'
import { removeall } from './helper.ts'
import { courseSeeds } from './seeds/course.ts'
import { discussionSeeds } from './seeds/discussion.ts'
import { groupSeeds } from './seeds/group.ts'
import { problemSeeds } from './seeds/problem.ts'
import { solutionSeeds } from './seeds/solution.ts'
import { userSeeds } from './seeds/user.ts'

function passwordHash (password: string): string {
  const bytes = Uint8Array.from(Buffer.from(password))
  return Buffer.concat([ md5(bytes), sha1(bytes) ]).toString('hex')
}

// The discussion service's createDiscussion: the discussion, its first comment and the statistics job.
async function createDiscussion (redis: Redis, discussion: Record<string, any>) {
  const { author, problem, contest, type, title, content } = discussion
  const created = new Discussion({ author, problem, contest, type, title })
  await created.save()
  await new Comment({ discussion: created._id, author, content }).save()
  const id = `discussion:${created._id.toString()}`
  if (!await redis.sismember('worker:updateStatistic:set', id)) {
    await redis.multi().sadd('worker:updateStatistic:set', id).rpush('worker:updateStatistic', id).exec()
  }
}

async function main () {
  await removeall()
  if (process.argv.includes('--clean')) {
    return
  }
  await Promise.all([
    Comment.syncIndexes(),
    Course.syncIndexes(),
    Discussion.syncIndexes(),
    Group.syncIndexes(),
    Solution.syncIndexes(),
    User.syncIndexes(),
  ])
  await Promise.all([
    new ID({ name: 'Contest', id: 0 }).save(),
    new ID({ name: 'Problem', id: 999 }).save(),
    new ID({ name: 'Solution', id: 0 }).save(),
  ])

  const courseInsert = Promise.all(
    courseSeeds.map(item => new Course(item).save()),
  )
  const groupInsert = Promise.all(
    groupSeeds.map(item => new Group(item).save()),
  )
  const problemInsert = (async () => {
    for (const problem of problemSeeds) {
      await new Problem(problem).save()
    }
  })()
  const userInsert = (async () => {
    await Promise.all(
      Object.values(userSeeds).map((user) => {
        return new User(Object.assign({}, user, {
          pwd: passwordHash(user.pwd as string),
        })).save()
      }),
    )
    await new User({
      uid: 'ghost',
      nick: 'ghost',
      pwd: passwordHash(randomUUID()),
    }).save()
  })()

  await Promise.all([
    courseInsert,
    groupInsert,
    problemInsert,
    userInsert,
  ])

  const solutionInsert = (async () => {
    const users = await User.find({})
    const userByUid = new Map(users.map(user => [ user.uid, user ]))
    const ghost = userByUid.get('ghost')!
    const problems = await Problem.find({})
    const problemByPid = new Map(problems.map(problem => [ problem.pid, problem ]))
    const solutions = []

    for (const solutionSeed of solutionSeeds) {
      const { uid, pid, ...solution } = solutionSeed
      const user = userByUid.get(uid) ?? ghost
      const problem = problemByPid.get(pid)
      if (!problem) {
        throw new Error(`Problem ${pid} not found while seeding solutions`)
      }
      solutions.push(await new Solution({ ...solution, problem: problem._id, user: user._id }).save())
    }

    const similarSolution = solutions.find(solution => solution.similarity > 0)
    const targetSolution = solutions.find(solution => solution.sid === 2)
    if (similarSolution && targetSolution) {
      similarSolution.similarSolution = targetSolution._id
      await similarSolution.save()
    }
  })()
  await solutionInsert

  // Seed discussions - must be done after users and problems
  const redis = new Redis(redisURL)
  const discussionInsert = (async () => {
    for (const discussionSeed of discussionSeeds) {
      const author = await User.findOne({ uid: discussionSeed.authorUid })
      if (!author) {
        console.error(`Author ${discussionSeed.authorUid} not found`)
        continue
      }

      let problem = null
      if (discussionSeed.problemPid) {
        problem = await Problem.findOne({ pid: discussionSeed.problemPid })
        if (!problem) {
          console.error(`Problem ${discussionSeed.problemPid} not found`)
        }
      }

      await createDiscussion(redis, {
        author: author._id,
        problem: problem?._id || null,
        contest: null,
        type: discussionSeed.type,
        title: discussionSeed.title,
        content: discussionSeed.content,
      })
    }
  })()

  await discussionInsert
  redis.disconnect()
}

main()
  .then(async () => {
    await disconnectMongoose()
    process.exit(0)
  }, (err) => {
    console.error(err)
    process.exit(1)
  })
