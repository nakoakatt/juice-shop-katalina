/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import models = require('../models/index')
import { type Request, type Response, type NextFunction } from 'express'
import { type User } from '../data/types'
import { BasketModel } from '../models/basket'
import { UserModel } from '../models/user'
import challengeUtils = require('../lib/challengeUtils')
import config from 'config'
import { challenges } from '../data/datacache'

import * as utils from '../lib/utils'
const security = require('../lib/insecurity')
const users = require('../data/datacache').users

const MIN_PASSWORD_LENGTH = 8
const MAX_PASSWORD_LENGTH = 64
const MAX_LOGIN_ATTEMPTS = 5
const LOCKOUT_TIME = 15 * 60 * 1000 // 15 minutes in milliseconds

module.exports = function login() {
  function afterLogin(user: { data: User, bid: number }, res: Response, next: NextFunction) {
    verifyPostLoginChallenges(user)
    BasketModel.findOrCreate({ where: { UserId: user.data.id } })
      .then(([basket]: [BasketModel, boolean]) => {
        const token = security.authorize(user)
        user.bid = basket.id
        security.authenticatedUsers.put(token, user)
        res.json({ authentication: { token, bid: basket.id, umail: user.data.email } })
      }).catch((error: Error) => {
        next(error)
      })
  }

  return async (req: Request, res: Response, next: NextFunction) => {
    const password = req.body.password || ''
    const email = req.body.email || ''

    // Password length validation
    if (password.length < MIN_PASSWORD_LENGTH || password.length > MAX_PASSWORD_LENGTH) {
      return res.status(400).send({ error: 'Password must be between 8 and 64 characters long.' })
    }

    try {
      // Check for the user in the database
      const user = await UserModel.findOne({ where: { email } })
      if (!user) {
        return res.status(401).send({ error: 'Invalid email or password.' })
      }

      // Check for account lockout
      if (user.lockoutUntil && new Date() < new Date(user.lockoutUntil)) {
        return res.status(429).send({ error: 'Account is locked. Please try again later.' })
      }

      verifyPreLoginChallenges(req)

      // Validate the password
      const isPasswordValid = security.hash(password) === user.password
      if (!isPasswordValid) {
        // Increment failed login attempts
        user.failedLoginAttempts = (user.failedLoginAttempts || 0) + 1

        // Lock the account if attempts exceed the threshold
        if (user.failedLoginAttempts >= MAX_LOGIN_ATTEMPTS) {
          user.lockoutUntil = new Date(Date.now() + LOCKOUT_TIME) // Lock for 15 minutes
          user.failedLoginAttempts = 0 // Reset attempts after locking
        }

        await user.save() // Save changes to the database

        return res.status(401).send({ error: 'Invalid email or password.' })
      }

      // Reset failed login attempts and lockout status on successful login
      user.failedLoginAttempts = 0
      user.lockoutUntil = null
      await user.save()

      // Proceed with post-login logic
      const authenticatedUser = user.get({ plain: true }) as User
      afterLogin({ data: authenticatedUser, bid: 0 }, res, next) // `bid: 0` temporarily, replaced after basket creation
    } catch (error) {
      next(error)
    }
  }

  function verifyPreLoginChallenges(req: Request) {
    challengeUtils.solveIf(challenges.weakPasswordChallenge, () => {
      return req.body.email === 'admin@' + config.get<string>('application.domain') && req.body.password === 'admin123'
    })
    challengeUtils.solveIf(challenges.loginSupportChallenge, () => {
      return req.body.email === 'support@' + config.get<string>('application.domain') && req.body.password === 'J6aVjTgOpRs@?5l!Zkq2AYnCE@RF$P'
    })
    challengeUtils.solveIf(challenges.loginRapperChallenge, () => {
      return req.body.email === 'mc.safesearch@' + config.get<string>('application.domain') && req.body.password === 'Mr. N00dles'
    })
    challengeUtils.solveIf(challenges.loginAmyChallenge, () => {
      return req.body.email === 'amy@' + config.get<string>('application.domain') && req.body.password === 'K1f.....................'
    })
    challengeUtils.solveIf(challenges.dlpPasswordSprayingChallenge, () => {
      return req.body.email === 'J12934@' + config.get<string>('application.domain') && req.body.password === '0Y8rMnww$*9VFYE§59-!Fg1L6t&6lB'
    })
    challengeUtils.solveIf(challenges.oauthUserPasswordChallenge, () => {
      return req.body.email === 'bjoern.kimminich@gmail.com' && req.body.password === 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
    })
  }

  function verifyPostLoginChallenges(user: { data: User }) {
    challengeUtils.solveIf(challenges.loginAdminChallenge, () => { return user.data.id === users.admin.id })
    challengeUtils.solveIf(challenges.loginJimChallenge, () => { return user.data.id === users.jim.id })
    challengeUtils.solveIf(challenges.loginBenderChallenge, () => { return user.data.id === users.bender.id })
    challengeUtils.solveIf(challenges.ghostLoginChallenge, () => { return user.data.id === users.chris.id })
    if (challengeUtils.notSolved(challenges.ephemeralAccountantChallenge) && user.data.email === 'acc0unt4nt@' + config.get<string>('application.domain') && user.data.role === 'accounting') {
      UserModel.count({ where: { email: 'acc0unt4nt@' + config.get<string>('application.domain') } }).then((count: number) => {
        if (count === 0) {
          challengeUtils.solve(challenges.ephemeralAccountantChallenge)
        }
      }).catch(() => {
        throw new Error('Unable to verify challenges! Try again')
      })
    }
  }
}
