// Store connections for the unit specs of server modules: MongoDB through @putong-oj/db and one Redis client,
// both from the suite's environment (see e2e.ts).
import { Redis } from 'ioredis'
import { redisURL } from './e2e.ts'

export const redis = new Redis(redisURL)
