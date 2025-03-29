import models = require("../models/index");
import { type Request, type Response, type NextFunction } from "express";
import { type User } from "../data/types";
import { BasketModel } from "../models/basket";
import { UserModel } from "../models/user";
import challengeUtils = require("../lib/challengeUtils");
import config from "config";
import { challenges } from "../data/datacache";
import { Op } from "sequelize";

import * as utils from "../lib/utils";
const security = require("../lib/insecurity");
const users = require("../data/datacache").users;
import validator from "validator";
import bcrypt from "bcrypt";
import winston from "winston"; // ✅ Import Winston for logging

// ✅ Logger setup (Logs to console + file)
const logger = winston.createLogger({
  level: "debug", // Logs everything from 'debug' level and above
  format: winston.format.simple(),
  transports: [
    new winston.transports.Console(), // ✅ Logs to console
    new winston.transports.File({ filename: "security.log" }), // ✅ Logs to file
  ],
});

module.exports = function login() {
  function afterLogin(
    user: { data: User; bid: number },
    res: Response,
    next: NextFunction
  ) {
    verifyPostLoginChallenges(user);

    BasketModel.findOrCreate({ where: { UserId: user.data.id } })
      .then(([basket]: [BasketModel, boolean]) => {
        const token = security.authorize(user);
        user.bid = basket.id;
        security.authenticatedUsers.put(token, user);

        logger.info(
          `✅ SUCCESS: User ${user.data.email} logged in successfully.`
        );

        res.json({
          authentication: { token, bid: basket.id, umail: user.data.email },
        });
      })
      .catch((error: Error) => {
        logger.error(
          `❌ ERROR: Failed to create basket for ${user.data.email}: ${error.message}`
        );
        next(error);
      });
  }

  return async (req: Request, res: Response, next: NextFunction) => {
    const email = req.body.email;
    const password = req.body.password;

    logger.info(`🔄 LOGIN ATTEMPT: ${email}`);

    if (!validator.isEmail(email)) {
      logger.warn(`⚠️ WARNING: Invalid email format: ${email}`);
      console.info(`⚠️ WARNING: Invalid email format: ${email}`); // Log to console
      return res.status(400).json({ error: "Invalid email format" });
    }

    if (!validator.isStrongPassword(password)) {
      logger.warn(`⚠️ WARNING: Weak password attempt from: ${email}`);
      console.info(`⚠️ WARNING: Weak password attempt from: ${email}`); // Log to console
      return res
        .status(400)
        .json({ error: "Password does not meet security standards" });
    }

    try {
      const authenticatedUser = await UserModel.findOne({
        where: { email: { [Op.eq]: email } },
      });

      if (!authenticatedUser) {
        logger.warn(`❌ FAILED LOGIN: ${email} (User not found)`);
        console.info(`❌ FAILED LOGIN: ${email} (User not found)`); // Log to console
        return res.status(401).send(res.__("Invalid email or password."));
      }

      logger.debug(`🔍 Checking password for ${email}`);

      const isPasswordValid = await bcrypt.compare(
        password,
        authenticatedUser.password
      );
      if (!isPasswordValid) {
        logger.warn(`❌ FAILED LOGIN: ${email} (Incorrect password)`);
        console.info(`❌ FAILED LOGIN: ${email} (Incorrect password)`); // Log to console
        return res.status(401).send(res.__("Invalid email or password."));
      }

      logger.info(`✅ SUCCESS: User ${email} authenticated`);
      console.info(`✅ SUCCESS: User ${email} authenticated`); // Log to console

      const user = {
        data: utils.queryResultToJson(authenticatedUser).data,
        bid: 0,
      };

      const [basket] = await BasketModel.findOrCreate({
        where: { UserId: user.data.id },
      });
      user.bid = basket.id;

      afterLogin(user, res, next);
    } catch (error: unknown) {
      const err = error as Error; // ✅ Cast error to Error type
      logger.error(`❌ ERROR: Login error for ${email}: ${err.message}`);
      console.info(`❌ ERROR: Login error for ${email}: ${err.message}`); // Log to console
      next(err);
    }
  };

  function verifyPreLoginChallenges(req: Request) {
    challengeUtils.solveIf(challenges.weakPasswordChallenge, () => {
      return (
        req.body.email ===
          "admin@" + config.get<string>("application.domain") &&
        req.body.password === "admin123"
      );
    });
    challengeUtils.solveIf(challenges.loginSupportChallenge, () => {
      return (
        req.body.email ===
          "support@" + config.get<string>("application.domain") &&
        req.body.password === "J6aVjTgOpRs@?5l!Zkq2AYnCE@RF$P"
      );
    });
    challengeUtils.solveIf(challenges.loginRapperChallenge, () => {
      return (
        req.body.email ===
          "mc.safesearch@" + config.get<string>("application.domain") &&
        req.body.password === "Mr. N00dles"
      );
    });
    challengeUtils.solveIf(challenges.loginAmyChallenge, () => {
      return (
        req.body.email === "amy@" + config.get<string>("application.domain") &&
        req.body.password === "K1f....................."
      );
    });
    challengeUtils.solveIf(challenges.dlpPasswordSprayingChallenge, () => {
      return (
        req.body.email ===
          "J12934@" + config.get<string>("application.domain") &&
        req.body.password === "0Y8rMnww$*9VFYE§59-!Fg1L6t&6lB"
      );
    });
    challengeUtils.solveIf(challenges.oauthUserPasswordChallenge, () => {
      return (
        req.body.email === "bjoern.kimminich@gmail.com" &&
        req.body.password === "bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI="
      );
    });
    challengeUtils.solveIf(challenges.exposedCredentialsChallenge, () => {
      return (
        req.body.email ===
          "testing@" + config.get<string>("application.domain") &&
        req.body.password === "IamUsedForTesting"
      );
    });
  }

  function verifyPostLoginChallenges(user: { data: User }) {
    challengeUtils.solveIf(challenges.loginAdminChallenge, () => {
      return user.data.id === users.admin.id;
    });
    challengeUtils.solveIf(challenges.loginJimChallenge, () => {
      return user.data.id === users.jim.id;
    });
    challengeUtils.solveIf(challenges.loginBenderChallenge, () => {
      return user.data.id === users.bender.id;
    });
    challengeUtils.solveIf(challenges.ghostLoginChallenge, () => {
      return user.data.id === users.chris.id;
    });
    if (
      challengeUtils.notSolved(challenges.ephemeralAccountantChallenge) &&
      user.data.email ===
        "acc0unt4nt@" + config.get<string>("application.domain") &&
      user.data.role === "accounting"
    ) {
      UserModel.count({
        where: {
          email: "acc0unt4nt@" + config.get<string>("application.domain"),
        },
      })
        .then((count: number) => {
          if (count === 0) {
            challengeUtils.solve(challenges.ephemeralAccountantChallenge);
          }
        })
        .catch(() => {
          throw new Error("Unable to verify challenges! Try again");
        });
    }
  }
};
