
import dataErasure from './routes/dataErasure'
import fs = require('fs')
import https=require('https')
import { type Request, type Response, type NextFunction } from 'express'
import { sequelize } from './models'
import { UserModel } from './models/user'
import { QuantityModel } from './models/quantity'
import { CardModel } from './models/card'
import { PrivacyRequestModel } from './models/privacyRequests'
import { AddressModel } from './models/address'
import { SecurityAnswerModel } from './models/securityAnswer'
import { SecurityQuestionModel } from './models/securityQuestion'
import { RecycleModel } from './models/recycle'
import { ComplaintModel } from './models/complaint'
import { ChallengeModel } from './models/challenge'
import { BasketItemModel } from './models/basketitem'
import { FeedbackModel } from './models/feedback'
import { ProductModel } from './models/product'
import { WalletModel } from './models/wallet'
import logger from './lib/logger'
import config from 'config'
import path from 'path'
import morgan from 'morgan'
import colors from 'colors/safe'
import * as utils from './lib/utils'
import * as Prometheus from 'prom-client'
import datacreator from './data/datacreator'

import validatePreconditions from './lib/startup/validatePreconditions'
import cleanupFtpFolder from './lib/startup/cleanupFtpFolder'
import validateConfig from './lib/startup/validateConfig'
import restoreOverwrittenFilesWithOriginals from './lib/startup/restoreOverwrittenFilesWithOriginals'
import registerWebsocketEvents from './lib/startup/registerWebsocketEvents'
import customizeApplication from './lib/startup/customizeApplication'
import customizeEasterEgg from './lib/startup/customizeEasterEgg' 

import authenticatedUsers from './routes/authenticatedUsers'

const startTime = Date.now()
const finale = require('finale-rest')
const express = require('express')
const compression = require('compression')
const helmet = require('helmet')
const featurePolicy = require('feature-policy')
const errorhandler = require('errorhandler')
const cookieParser = require('cookie-parser')
const serveIndex = require('serve-index')
const bodyParser = require('body-parser')
const cors = require('cors')
const securityTxt = require('express-security.txt')
const robots = require('express-robots-txt')
const yaml = require('js-yaml')
const swaggerUi = require('swagger-ui-express')
const RateLimit = require('express-rate-limit')
const ipfilter = require('express-ipfilter').IpFilter
const swaggerDocument = yaml.load(fs.readFileSync('./swagger.yml', 'utf8'))
const {
  ensureFileIsPassed,
  handleZipFileUpload,
  checkUploadSize,
  checkFileType,
  handleXmlUpload,
  handleYamlUpload
} = require('./routes/fileUpload')
const profileImageFileUpload = require('./routes/profileImageFileUpload')
const profileImageUrlUpload = require('./routes/profileImageUrlUpload')
const redirect = require('./routes/redirect')
const vulnCodeSnippet = require('./routes/vulnCodeSnippet')
const vulnCodeFixes = require('./routes/vulnCodeFixes')
const angular = require('./routes/angular')
const easterEgg = require('./routes/easterEgg')
const premiumReward = require('./routes/premiumReward')
const privacyPolicyProof = require('./routes/privacyPolicyProof')
const appVersion = require('./routes/appVersion')
const repeatNotification = require('./routes/repeatNotification')
const continueCode = require('./routes/continueCode')
const restoreProgress = require('./routes/restoreProgress')
const fileServer = require('./routes/fileServer')
const quarantineServer = require('./routes/quarantineServer')
const keyServer = require('./routes/keyServer')
const logFileServer = require('./routes/logfileServer')
const metrics = require('./routes/metrics')
const currentUser = require('./routes/currentUser')
const login = require('./routes/login')
const changePassword = require('./routes/changePassword')
const resetPassword = require('./routes/resetPassword')
const securityQuestion = require('./routes/securityQuestion')
const search = require('./routes/search')
const coupon = require('./routes/coupon')
const basket = require('./routes/basket')
const order = require('./routes/order')
const verify = require('./routes/verify')
const recycles = require('./routes/recycles')
const b2bOrder = require('./routes/b2bOrder')
const showProductReviews = require('./routes/showProductReviews')
const createProductReviews = require('./routes/createProductReviews')
const checkKeys = require('./routes/checkKeys')
const nftMint = require('./routes/nftMint')
const web3Wallet = require('./routes/web3Wallet')
const updateProductReviews = require('./routes/updateProductReviews')
const likeProductReviews = require('./routes/likeProductReviews')
const security = require('./lib/insecurity')
const app = express()
const options = {
  key: fs.readFileSync('path/to/your/private-key.pem'),
  cert: fs.readFileSync('path/to/your/certificate.pem'),
};
const server = https.createServer(options, app);

const appConfiguration = require('./routes/appConfiguration')
const captcha = require('./routes/captcha')
const trackOrder = require('./routes/trackOrder')
const countryMapping = require('./routes/countryMapping')
const basketItems = require('./routes/basketItems')
const saveLoginIp = require('./routes/saveLoginIp')
const userProfile = require('./routes/userProfile')
const updateUserProfile = require('./routes/updateUserProfile')
const videoHandler = require('./routes/videoHandler')
const twoFactorAuth = require('./routes/2fa')
const languageList = require('./routes/languages')
const imageCaptcha = require('./routes/imageCaptcha')
const dataExport = require('./routes/dataExport')
const address = require('./routes/address')
const payment = require('./routes/payment')
const wallet = require('./routes/wallet')
const orderHistory = require('./routes/orderHistory')
const delivery = require('./routes/delivery')
const deluxe = require('./routes/deluxe')
const memory = require('./routes/memory')
const chatbot = require('./routes/chatbot')
const locales = require('./data/static/locales.json')
const i18n = require('i18n')
const antiCheat = require('./lib/antiCheat')

const appName = config.get<string>('application.customMetricsPrefix')
const startupGauge = new Prometheus.Gauge({
  name: `${appName}_startup_duration_seconds`,
  help: `Duration ${appName} required to perform a certain task during startup`,
  labelNames: ['task']
})


const collectDurationPromise = (name: string, func: (...args: any) => Promise<any>) => {
  return async (...args: any) => {
    const end = startupGauge.startTimer({ task: name })
    try {
      const res = await func(...args)
      end()
      return res
    } catch (err) {
      console.error('Error in timed startup function: ' + name, err)
      throw err
    }
  }
}


app.set('view engine', 'hbs')

void collectDurationPromise('validatePreconditions', validatePreconditions)()
void collectDurationPromise('cleanupFtpFolder', cleanupFtpFolder)()
void collectDurationPromise('validateConfig', validateConfig)({})


restoreOverwrittenFilesWithOriginals().then(() => {
 
  app.locals.captchaId = 0
  app.locals.captchaReqId = 1
  app.locals.captchaBypassReqTimes = []
  app.locals.abused_ssti_bug = false
  app.locals.abused_ssrf_bug = false

 
  app.use(compression())

 
  app.options('*', cors())
  app.use(cors())

 
  app.use(helmet.noSniff())
  app.use(helmet.frameguard())
  
  app.disable('x-powered-by')
  app.use(featurePolicy({
    features: {
      payment: ["'self'"]
    }
  }))

 
  app.use((req: Request, res: Response, next: NextFunction) => {
    res.append('X-Recruiting', config.get('application.securityTxt.hiring'))
    next()
  })

 
  app.use((req: Request, res: Response, next: NextFunction) => {
    req.url = req.url.replace(/[/]+/g, '/')
    next()
  })

 
  app.use(metrics.observeRequestMetricsMiddleware())

 
  const securityTxtExpiration = new Date()
  securityTxtExpiration.setFullYear(securityTxtExpiration.getFullYear() + 1)
  app.get(['/.well-known/security.txt', '/security.txt'], verify.accessControlChallenges())
  app.use(['/.well-known/security.txt', '/security.txt'], securityTxt({
    contact: config.get('application.securityTxt.contact'),
    encryption: config.get('application.securityTxt.encryption'),
    acknowledgements: config.get('application.securityTxt.acknowledgements'),
    'Preferred-Languages': [...new Set(locales.map((locale: { key: string }) => locale.key.substr(0, 2)))].join(', '),
    hiring: config.get('application.securityTxt.hiring'),
    csaf: config.get<string>('server.baseUrl') + config.get<string>('application.securityTxt.csaf'),
    expires: securityTxtExpiration.toUTCString()
  }))

 
  app.use(robots({ UserAgent: '*', Disallow: '/ftp' }))

 
  app.use(antiCheat.checkForPreSolveInteractions())

 
  app.use('/assets/public/images/padding', verify.accessControlChallenges())
  app.use('/assets/public/images/products', verify.accessControlChallenges())
  app.use('/assets/public/images/uploads', verify.accessControlChallenges())
  app.use('/assets/i18n', verify.accessControlChallenges())

 
  app.use('/solve/challenges/server-side', verify.serverSideChallenges())

 
  const serveIndexMiddleware = (req: Request, res: Response, next: NextFunction) => {
    const origEnd = res.end
    
    res.end = function () {
      if (arguments.length) {
        const reqPath = req.originalUrl.replace(/\?.*$/, '')
        const currentFolder = reqPath.split('/').pop() as string
        arguments[0] = arguments[0].replace(/a href="([^"]+?)"/gi, function (matchString: string, matchedUrl: string) {
          let relativePath = path.relative(reqPath, matchedUrl)
          if (relativePath === '') {
            relativePath = currentFolder
          } else if (!relativePath.startsWith('.') && currentFolder !== '') {
            relativePath = currentFolder + '/' + relativePath
          } else {
            relativePath = relativePath.replace('..', '.')
          }
          return 'a href="' + relativePath + '"'
        })
      }
      
      origEnd.apply(this, arguments)
    }
    next()
  }

  
  
  app.use('/ftp', serveIndexMiddleware, serveIndex('ftp', { icons: true })) 
  app.use('/ftp(?!/quarantine)/:file', fileServer()) 
  app.use('/ftp/quarantine/:file', quarantineServer()) 

  app.use('/.well-known', serveIndexMiddleware, serveIndex('.well-known', { icons: true, view: 'details' }))
  app.use('/.well-known', express.static('.well-known'))

 
  app.use('/encryptionkeys', serveIndexMiddleware, serveIndex('encryptionkeys', { icons: true, view: 'details' }))
  app.use('/encryptionkeys/:file', keyServer())

  
  app.use('/support/logs', serveIndexMiddleware, serveIndex('logs', { icons: true, view: 'details' })) 
  app.use('/support/logs', verify.accessControlChallenges()) 
  app.use('/support/logs/:file', logFileServer()) 

 
  app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument))

  app.use(express.static(path.resolve('frontend/dist/frontend')))
  app.use(cookieParser('kekse'))
  

 
  i18n.configure({
    locales: locales.map((locale: { key: string }) => locale.key),
    directory: path.resolve('i18n'),
    cookie: 'language',
    defaultLocale: 'en',
    autoReload: true
  })
  app.use(i18n.init)

  app.use(bodyParser.urlencoded({ extended: true }))
 
  app.post('/file-upload', uploadToMemory.single('file'), ensureFileIsPassed, metrics.observeFileUploadMetricsMiddleware(), checkUploadSize, checkFileType, handleZipFileUpload, handleXmlUpload, handleYamlUpload)
  app.post('/profile/image/file', uploadToMemory.single('file'), ensureFileIsPassed, metrics.observeFileUploadMetricsMiddleware(), profileImageFileUpload())
  app.post('/profile/image/url', uploadToMemory.single('file'), profileImageUrlUpload())
  app.post('/rest/memories', uploadToDisk.single('image'), ensureFileIsPassed, security.appendUserId(), metrics.observeFileUploadMetricsMiddleware(), memory.addMemory())

  app.use(bodyParser.text({ type: '*/*' }))
  app.use(function jsonParser (req: Request, res: Response, next: NextFunction) {
    
    req.rawBody = req.body
    if (req.headers['content-type']?.includes('application/json')) {
      if (!req.body) {
        req.body = {}
      }
      if (req.body !== Object(req.body)) { 
        req.body = JSON.parse(req.body)
      }
    }
    next()
  })

 
  const accessLogStream = require('file-stream-rotator').getStream({
    filename: path.resolve('logs/access.log'),
    frequency: 'daily',
    verbose: false,
    max_logs: '2d'
  })
  app.use(morgan('combined', { stream: accessLogStream }))

  
 
  app.enable('trust proxy')
  app.use('/rest/user/reset-password', new RateLimit({
    windowMs: 5 * 60 * 1000,
    max: 100,
    keyGenerator ({ headers, ip }: { headers: any, ip: any }) { return headers['X-Forwarded-For'] ?? ip } 
  }))
  

  
  /** Authorization **/
  
  app.use(verify.jwtChallenges()) 
 
  app.use('/rest/basket', security.isAuthorized(), security.appendUserId())
 
  app.use('/api/BasketItems', security.isAuthorized())
  app.use('/api/BasketItems/:id', security.isAuthorized())
 
  app.use('/api/Feedbacks/:id', security.isAuthorized())
 
  app.get('/api/Users', security.isAuthorized())
  app.route('/api/Users/:id')
    .get(security.isAuthorized())
    .put(security.denyAll())
    .delete(security.denyAll())
  
  app.post('/api/Products', security.isAuthorized()) 
  
  app.delete('/api/Products/:id', security.denyAll())
 
  app.post('/api/Challenges', security.denyAll())
  app.use('/api/Challenges/:id', security.denyAll())
 
  app.get('/api/Complaints', security.isAuthorized())
  app.post('/api/Complaints', security.isAuthorized())
  app.use('/api/Complaints/:id', security.denyAll())
 
  app.get('/api/Recycles', recycles.blockRecycleItems())
  app.post('/api/Recycles', security.isAuthorized())
 
  app.get('/api/Recycles/:id', recycles.getRecycleItem())
  app.put('/api/Recycles/:id', security.denyAll())
  app.delete('/api/Recycles/:id', security.denyAll())
 
  app.post('/api/SecurityQuestions', security.denyAll())
  app.use('/api/SecurityQuestions/:id', security.denyAll())
 
  app.get('/api/SecurityAnswers', security.denyAll())
  app.use('/api/SecurityAnswers/:id', security.denyAll())
 
  app.use('/rest/user/authentication-details', security.isAuthorized())
  app.use('/rest/basket/:id', security.isAuthorized())
  app.use('/rest/basket/:id/order', security.isAuthorized())
  
  app.post('/api/Feedbacks', verify.forgedFeedbackChallenge())
 
  app.post('/api/Feedbacks', captcha.verifyCaptcha())
 
  app.post('/api/Feedbacks', verify.captchaBypassChallenge())
 
  app.post('/api/Users', (req: Request, res: Response, next: NextFunction) => {
    if (req.body.email !== undefined && req.body.password !== undefined && req.body.passwordRepeat !== undefined) {
      if (req.body.email.length !== 0 && req.body.password.length !== 0) {
        req.body.email = req.body.email.trim()
        req.body.password = req.body.password.trim()
        req.body.passwordRepeat = req.body.passwordRepeat.trim()
      } else {
        res.status(400).send(res.__('Invalid email/password cannot be empty'))
      }
    }
    next()
  })
  app.post('/api/Users', verify.registerAdminChallenge())
  app.post('/api/Users', verify.passwordRepeatChallenge()) 
  app.post('/api/Users', verify.emptyUserRegistration())
 
  app.use('/b2b/v2', security.isAuthorized())
 
  app.put('/api/BasketItems/:id', security.appendUserId(), basketItems.quantityCheckBeforeBasketItemUpdate())
  app.post('/api/BasketItems', security.appendUserId(), basketItems.quantityCheckBeforeBasketItemAddition(), basketItems.addBasketItem())
 
  app.delete('/api/Quantitys/:id', security.denyAll())
  app.post('/api/Quantitys', security.denyAll())
  app.use('/api/Quantitys/:id', security.isAccounting(), ipfilter(['123.456.789'], { mode: 'allow' }))
 
  app.put('/api/Feedbacks/:id', security.denyAll())
 
  app.use('/api/PrivacyRequests', security.isAuthorized())
  app.use('/api/PrivacyRequests/:id', security.isAuthorized())
 
  app.post('/api/Cards', security.appendUserId())
  app.get('/api/Cards', security.appendUserId(), payment.getPaymentMethods())
  app.put('/api/Cards/:id', security.denyAll())
  app.delete('/api/Cards/:id', security.appendUserId(), payment.delPaymentMethodById())
  app.get('/api/Cards/:id', security.appendUserId(), payment.getPaymentMethodById())
 
  app.post('/api/PrivacyRequests', security.isAuthorized())
  app.get('/api/PrivacyRequests', security.denyAll())
  app.use('/api/PrivacyRequests/:id', security.denyAll())

  app.post('/api/Addresss', security.appendUserId())
  app.get('/api/Addresss', security.appendUserId(), address.getAddress())
  app.put('/api/Addresss/:id', security.appendUserId())
  app.delete('/api/Addresss/:id', security.appendUserId(), address.delAddressById())
  app.get('/api/Addresss/:id', security.appendUserId(), address.getAddressById())
  app.get('/api/Deliverys', delivery.getDeliveryMethods())
  app.get('/api/Deliverys/:id', delivery.getDeliveryMethod())
  

 
  app.post('/rest/2fa/verify',
    new RateLimit({ windowMs: 5 * 60 * 1000, max: 100 }),
    twoFactorAuth.verify()
  )
 
  app.get('/rest/2fa/status', security.isAuthorized(), twoFactorAuth.status())
 
  app.post('/rest/2fa/setup',
    new RateLimit({ windowMs: 5 * 60 * 1000, max: 100 }),
    security.isAuthorized(),
    twoFactorAuth.setup()
  )
 
  app.post('/rest/2fa/disable',
    new RateLimit({ windowMs: 5 * 60 * 1000, max: 100 }),
    security.isAuthorized(),
    twoFactorAuth.disable()
  )
 
  app.use(verify.databaseRelatedChallenges())

  
 
  finale.initialize({ app, sequelize })

  const autoModels = [
    { name: 'User', exclude: ['password', 'totpSecret'], model: UserModel },
    { name: 'Product', exclude: [], model: ProductModel },
    { name: 'Feedback', exclude: [], model: FeedbackModel },
    { name: 'BasketItem', exclude: [], model: BasketItemModel },
    { name: 'Challenge', exclude: [], model: ChallengeModel },
    { name: 'Complaint', exclude: [], model: ComplaintModel },
    { name: 'Recycle', exclude: [], model: RecycleModel },
    { name: 'SecurityQuestion', exclude: [], model: SecurityQuestionModel },
    { name: 'SecurityAnswer', exclude: [], model: SecurityAnswerModel },
    { name: 'Address', exclude: [], model: AddressModel },
    { name: 'PrivacyRequest', exclude: [], model: PrivacyRequestModel },
    { name: 'Card', exclude: [], model: CardModel },
    { name: 'Quantity', exclude: [], model: QuantityModel }
  ]

  for (const { name, exclude, model } of autoModels) {
    const resource = finale.resource({
      model,
      endpoints: [`/api/${name}s`, `/api/${name}s/:id`],
      excludeAttributes: exclude,
      pagination: false
    })

    
    if (name === 'User') { 
      resource.create.send.before((req: Request, res: Response, context: { instance: { id: any }, continue: any }) => { 
        WalletModel.create({ UserId: context.instance.id }).catch((err: unknown) => {
          console.log(err)
        })
        return context.continue 
      }) 
    } 
    

    
    if (name === 'Challenge') {
      resource.list.fetch.after((req: Request, res: Response, context: { instance: string | any[], continue: any }) => {
        for (let i = 0; i < context.instance.length; i++) {
          let description = context.instance[i].description
          if (utils.contains(description, '<em>(This challenge is <strong>')) {
            const warning = description.substring(description.indexOf(' <em>(This challenge is <strong>'))
            description = description.substring(0, description.indexOf(' <em>(This challenge is <strong>'))
            context.instance[i].description = req.__(description) + req.__(warning)
          } else {
            context.instance[i].description = req.__(description)
          }
          if (context.instance[i].hint) {
            context.instance[i].hint = req.__(context.instance[i].hint)
          }
        }
        return context.continue
      })
      resource.read.send.before((req: Request, res: Response, context: { instance: { description: string, hint: string }, continue: any }) => {
        context.instance.description = req.__(context.instance.description)
        if (context.instance.hint) {
          context.instance.hint = req.__(context.instance.hint)
        }
        return context.continue
      })
    }

    
    if (name === 'SecurityQuestion') {
      resource.list.fetch.after((req: Request, res: Response, context: { instance: string | any[], continue: any }) => {
        for (let i = 0; i < context.instance.length; i++) {
          context.instance[i].question = req.__(context.instance[i].question)
        }
        return context.continue
      })
      resource.read.send.before((req: Request, res: Response, context: { instance: { question: string }, continue: any }) => {
        context.instance.question = req.__(context.instance.question)
        return context.continue
      })
    }

    
    if (name === 'Product') {
      resource.list.fetch.after((req: Request, res: Response, context: { instance: any[], continue: any }) => {
        for (let i = 0; i < context.instance.length; i++) {
          context.instance[i].name = req.__(context.instance[i].name)
          context.instance[i].description = req.__(context.instance[i].description)
        }
        return context.continue
      })
      resource.read.send.before((req: Request, res: Response, context: { instance: { name: string, description: string }, continue: any }) => {
        context.instance.name = req.__(context.instance.name)
        context.instance.description = req.__(context.instance.description)
        return context.continue
      })
    }

    
    resource.all.send.before((req: Request, res: Response, context: { instance: { status: string, data: any }, continue: any }) => {
      context.instance = {
        status: 'success',
        data: context.instance
      }
      return context.continue
    })
  }

 
  app.post('/rest/user/login', login())
  app.get('/rest/user/change-password', changePassword())
  app.post('/rest/user/reset-password', resetPassword())
  app.get('/rest/user/security-question', securityQuestion())
  app.get('/rest/user/whoami', security.updateAuthenticatedUsers(), currentUser())
  app.get('/rest/user/authentication-details', authenticatedUsers())
  app.get('/rest/products/search', search())
  app.get('/rest/basket/:id', basket())
  app.post('/rest/basket/:id/checkout', order())
  app.put('/rest/basket/:id/coupon/:coupon', coupon())
  app.get('/rest/admin/application-version', appVersion())
  app.get('/rest/admin/application-configuration', appConfiguration())
  app.get('/rest/repeat-notification', repeatNotification())
  app.get('/rest/continue-code', continueCode.continueCode())
  app.get('/rest/continue-code-findIt', continueCode.continueCodeFindIt())
  app.get('/rest/continue-code-fixIt', continueCode.continueCodeFixIt())
  app.put('/rest/continue-code-findIt/apply/:continueCode', restoreProgress.restoreProgressFindIt())
  app.put('/rest/continue-code-fixIt/apply/:continueCode', restoreProgress.restoreProgressFixIt())
  app.put('/rest/continue-code/apply/:continueCode', restoreProgress.restoreProgress())
  app.get('/rest/admin/application-version', appVersion())
  app.get('/rest/captcha', captcha())
  app.get('/rest/image-captcha', imageCaptcha())
  app.get('/rest/track-order/:id', trackOrder())
  app.get('/rest/country-mapping', countryMapping())
  app.get('/rest/saveLoginIp', saveLoginIp())
  app.post('/rest/user/data-export', security.appendUserId(), imageCaptcha.verifyCaptcha())
  app.post('/rest/user/data-export', security.appendUserId(), dataExport())
  app.get('/rest/languages', languageList())
  app.get('/rest/order-history', orderHistory.orderHistory())
  app.get('/rest/order-history/orders', security.isAccounting(), orderHistory.allOrders())
  app.put('/rest/order-history/:id/delivery-status', security.isAccounting(), orderHistory.toggleDeliveryStatus())
  app.get('/rest/wallet/balance', security.appendUserId(), wallet.getWalletBalance())
  app.put('/rest/wallet/balance', security.appendUserId(), wallet.addWalletBalance())
  app.get('/rest/deluxe-membership', deluxe.deluxeMembershipStatus())
  app.post('/rest/deluxe-membership', security.appendUserId(), deluxe.upgradeToDeluxe())
  app.get('/rest/memories', memory.getMemories())
  app.get('/rest/chatbot/status', chatbot.status())
  app.post('/rest/chatbot/respond', chatbot.process())
 
  app.get('/rest/products/:id/reviews', showProductReviews())
  app.put('/rest/products/:id/reviews', createProductReviews())
  app.patch('/rest/products/reviews', security.isAuthorized(), updateProductReviews())
  app.post('/rest/products/reviews', security.isAuthorized(), likeProductReviews())

 
  app.post('/rest/web3/submitKey', checkKeys.checkKeys())
  app.get('/rest/web3/nftUnlocked', checkKeys.nftUnlocked())
  app.get('/rest/web3/nftMintListen', nftMint.nftMintListener())
  app.post('/rest/web3/walletNFTVerify', nftMint.walletNFTVerify())
  app.post('/rest/web3/walletExploitAddress', web3Wallet.contractExploitListener())

 
  app.post('/b2b/v2/orders', b2bOrder())

 
  app.get('/the/devs/are/so/funny/they/hid/an/easter/egg/within/the/easter/egg', easterEgg())
  app.get('/this/page/is/hidden/behind/an/incredibly/high/paywall/that/could/only/be/unlocked/by/sending/1btc/to/us', premiumReward())
  app.get('/we/may/also/instruct/you/to/refuse/all/reasonably/necessary/responsibility', privacyPolicyProof())

 
  app.use('/dataerasure', dataErasure)

 
  app.get('/redirect', redirect())

 
  app.get('/promotion', videoHandler.promotionVideo())
  app.get('/video', videoHandler.getVideo())

 
  app.get('/profile', security.updateAuthenticatedUsers(), userProfile())
  app.post('/profile', updateUserProfile())

 
  app.get('/snippets', vulnCodeSnippet.serveChallengesWithCodeSnippet())
  app.get('/snippets/:challenge', vulnCodeSnippet.serveCodeSnippet())
  app.post('/snippets/verdict', vulnCodeSnippet.checkVulnLines())
  app.get('/snippets/fixes/:key', vulnCodeFixes.serveCodeFixes())
  app.post('/snippets/fixes', vulnCodeFixes.checkCorrectFix())

  app.use(angular())

 
  app.use(verify.errorHandlingChallenge())
  app.use(errorhandler())
}).catch((err) => {
  console.error(err)
})

const multer = require('multer')
const uploadToMemory = multer({ storage: multer.memoryStorage(), limits: { fileSize: 200000 } })
const mimeTypeMap: any = {
  'image/png': 'png',
  'image/jpeg': 'jpg',
  'image/jpg': 'jpg'
}
const uploadToDisk = multer({
  storage: multer.diskStorage({
    destination: (req: Request, file: any, cb: any) => {
      const isValid = mimeTypeMap[file.mimetype]
      let error: Error | null = new Error('Invalid mime type')
      if (isValid) {
        error = null
      }
      cb(error, path.resolve('frontend/dist/frontend/assets/public/images/uploads/'))
    },
    filename: (req: Request, file: any, cb: any) => {
      const name = security.sanitizeFilename(file.originalname)
        .toLowerCase()
        .split(' ')
        .join('-')
      const ext = mimeTypeMap[file.mimetype]
      cb(null, name + '-' + Date.now() + '.' + ext)
    }
  })
})

const expectedModels = ['Address', 'Basket', 'BasketItem', 'Captcha', 'Card', 'Challenge', 'Complaint', 'Delivery', 'Feedback', 'ImageCaptcha', 'Memory', 'PrivacyRequestModel', 'Product', 'Quantity', 'Recycle', 'SecurityAnswer', 'SecurityQuestion', 'User', 'Wallet']
while (!expectedModels.every(model => Object.keys(sequelize.models).includes(model))) {
  logger.info(`Entity models ${colors.bold(Object.keys(sequelize.models).length.toString())} of ${colors.bold(expectedModels.length.toString())} are initialized (${colors.yellow('WAITING')})`)
}
logger.info(`Entity models ${colors.bold(Object.keys(sequelize.models).length.toString())} of ${colors.bold(expectedModels.length.toString())} are initialized (${colors.green('OK')})`)



let metricsUpdateLoop: any
const Metrics = metrics.observeMetrics() 
app.get('/metrics', metrics.serveMetrics()) 
errorhandler.title = `${config.get<string>('application.name')} (Express ${utils.version('express')})`

export async function start (readyCallback?: () => void) {
  const datacreatorEnd = startupGauge.startTimer({ task: 'datacreator' })
  await sequelize.sync({ force: true })
  await datacreator()
  datacreatorEnd()
  const port = process.env.PORT ?? config.get('server.port')
  process.env.BASE_PATH = process.env.BASE_PATH ?? config.get('server.basePath')
  logger.info(colors.cyan(`Server running locally on https:

  metricsUpdateLoop = Metrics.updateLoop() 

  server.listen(port, () => {
    logger.info(colors.cyan(`Server listening on  https:
    startupGauge.set({ task: 'ready' }, (Date.now() - startTime) / 1000)
    if (process.env.BASE_PATH !== '') {
      logger.info(colors.cyan(`Server using proxy base path ${colors.bold(`${process.env.BASE_PATH}`)} for redirects`))
    }
    registerWebsocketEvents(server)
    if (readyCallback) {
      readyCallback()
    }
  })

  void collectDurationPromise('customizeApplication', customizeApplication)() 
  void collectDurationPromise('customizeEasterEgg', customizeEasterEgg)() 
}

export function close (exitCode: number | undefined) {
  if (server) {
    clearInterval(metricsUpdateLoop)
    server.close()
  }
  if (exitCode !== undefined) {
    process.exit(exitCode)
  }
}



process.on('SIGINT', () => { close(0) })
process.on('SIGTERM', () => { close(0) })
