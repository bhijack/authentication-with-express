const express = require('express')
const app = express()
const port = 3000

const bodyParser = require('body-parser')
app.use(bodyParser.json())

const crypto = require('crypto')
const jwt = require('jsonwebtoken')

const mongo = require('mongodb')
const mongoURL = 'mongodb://'
const dbName = 'test_authen_system'
const collectionName = 'users'

const mongoClient = mongo.MongoClient
const auth = 'admin:admin'
const secret = 'bozshijack'

const validateBasic = (req, res, next) => {
    let basic = req.headers.authorization ? decodeBasicAuth(req.headers.authorization) : null
    if (basic !== auth) {
        res.status(401)
        return res.send(
            {
                status: 401,
                message: 'authentication failed'
            }
        )
    }
    next()
}

const decodeBasicAuth = (basicAuth) => {
    let decoded = null
    try {
        let tmp = basicAuth.split(' ')
        let buf = new Buffer.from(tmp[1], 'base64')
        decoded = buf.toString()
    } catch (error) {
        console.log(error)
    }
    return decoded
}

const validateToken = (req, res, next) => {
    let token = req.headers.authorization ? req.headers.authorization.split(' ')[1] : null
    if (!token) {
        res.status(400)
        return res.send({
            status: 400,
            message: 'Token missing'
        })
    }

    jwt.verify(token, secret, (err, data) => {
        if (err) {
            res.status(401)
            return res.send({
                status: 401,
                message: `[TOKEN ERROR] ${err}`
            })
        }

        let query = { '_id': mongo.ObjectID(data['id']) }

        mongoClient.connect(mongoURL, function (err, db) {
            if (err) {
                res.status(500)
                return res.send({
                    status: 500,
                    message: `Internal error : ${err}`
                })
            }
            let dbo = db.db(dbName)
            let collection = dbo.collection(collectionName)
            collection.findOne(query, function (err, result) {
                if (err) {
                    res.status(500)
                    return res.send({
                        status: 500,
                        message: `Internal error : ${err}`
                    })
                }
                db.close()
                if (!result) {
                    res.status(401)
                    return res.send({
                        status: 401,
                        data: 'invalid token'
                    })

                }
                next()
            })
        })
    })
}



app.post('/register', validateBasic, (req, res) => {
    let body = req.body

    if (!('username' in body) || !('password' in body)) {
        res.status(400)
        return res.send(
            {
                status: '400',
                message: 'username or password missing'
            }
        )
    }

    let hash = crypto.createHash('sha256').update(body['password']).digest('hex')
    let newUser = {
        'username': body['username'],
        'password': hash
    }

    mongoClient.connect(mongoURL, function (err, db) {
        if (err) {
            res.status(500)
            return res.send({
                status: 500,
                message: `Internal error : ${err}`
            })
        }
        let dbo = db.db(dbName)
        let collection = dbo.collection(collectionName)
        collection.insertOne(newUser, function (err, result) {
            if (err) {
                res.status(500)
                return res.send({
                    status: 500,
                    message: `Internal error : ${err}`
                })
            }
            db.close()
            let userInserted = result.ops[0]
            res.status(200)
            return res.send({
                status: 200,
                data: userInserted
            })
        })
    })
})

app.post('/login', validateBasic, (req, res) => {
    let body = req.body

    if (!('username' in body) || !('password' in body)) {
        res.status(400)
        return res.send(
            {
                status: '400',
                message: 'username or password missing'
            }
        )
    }

    let hash = crypto.createHash('sha256').update(body['password']).digest('hex')
    let loggedinUser = {
        'username': body['username'],
        'password': hash
    }

    mongoClient.connect(mongoURL, function (err, db) {
        if (err) {
            res.status(500)
            return res.send({
                status: 500,
                message: `Internal error : ${err}`
            })
        }
        let dbo = db.db(dbName)
        let collection = dbo.collection(collectionName)
        collection.findOne(loggedinUser, function (err, result) {
            if (err) {
                res.status(500)
                return res.send({
                    status: 500,
                    message: `Internal error : ${err}`
                })
            }
            db.close()
            if (!result) {
                res.status(404)
                return res.send({
                    status: 404,
                    data: 'login failed'
                })

            }
            let userId = result['_id'].toString()
            let token = jwt.sign({ id: userId }, secret, { expiresIn: '500s' })
            result['token'] = token

            res.status(200)
            return res.send({
                status: 200,
                data: result
            })
        })
    })

})

app.get('/test-token', validateToken, (req, res) => {
    return res.send({
        status : 200,
        message: 'login success'
    })
})



app.get('/', (req, res) => {
    return res.send({
        message: 'server running...'
    })
})

app.listen(port, () => {
    console.log(`running on port ${port}`)
})
