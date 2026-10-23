import { Comment, Contest, Course, CourseMember, Discussion, Files, Group, ID, OAuth, Post, Problem, Settings, Solution, Tag, User } from '@putong-oj/db'
import { Redis } from 'ioredis'
import { redisURL } from './e2e.ts'

export async function removeall () {
  const redis = new Redis(redisURL)
  try {
    await Promise.all([
      Comment.deleteMany({}),
      Contest.deleteMany({}),
      Course.deleteMany({}),
      CourseMember.deleteMany({}),
      Discussion.deleteMany({}),
      Files.deleteMany({}),
      Group.deleteMany({}),
      ID.deleteMany({}),
      OAuth.deleteMany({}),
      Post.deleteMany({}),
      Problem.deleteMany({}),
      Settings.deleteMany({}),
      Solution.deleteMany({}),
      Tag.deleteMany({}),
      User.deleteMany({}),
      redis.flushdb(),
    ])
  } finally {
    redis.disconnect()
  }
}
