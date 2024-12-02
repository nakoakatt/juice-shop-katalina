/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { UserModel } from '../models/user'
import challengeUtils = require('../lib/challengeUtils')
import * as utils from '../lib/utils'

const security = require('../lib/insecurity')
const cache = require('../data/datacache')
const challenges = cache.challenges

const MIN_PASSWORD_LENGTH = 8
const MAX_PASSWORD_LENGTH = 64

module.exports = function updateUserProfile () {
  return (req: Request, res: Response, next: NextFunction) => {
    const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
    const newPassword = req.body.newPassword

    // Password length validation
    if (newPassword && (newPassword.length < MIN_PASSWORD_LENGTH || newPassword.length > MAX_PASSWORD_LENGTH)) {
      return res.status(400).send({ error: 'Password must be between 8 and 64 characters long.' })
    }

    if (loggedInUser) {
      UserModel.findByPk(loggedInUser.data.id).then((user: UserModel | null) => {
        if (user != null) {
          // Update user details (username and optionally other fields)
          user.update({ username: req.body.username }).then((savedUser: UserModel) => {
            const updatedToken = security.authorize(savedUser)
            security.authenticatedUsers.put(updatedToken, savedUser)
            res.cookie('token', updatedToken)
            res.redirect(process.env.BASE_PATH + '/profile')
          })
        }
      }).catch((error: Error) => {
        next(error)
      })
    } else {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
    }
  }
}
