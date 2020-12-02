const express = require("express");
const mongodb = require("mongodb");
const nodemailer = require("nodemailer");
const cors = require("cors");
const bcrypt = require("bcrypt");
require("dotenv").config();
const cryptoRandomString = require('crypto-random-string');

const mongoClient = mongodb.MongoClient;
const objectId = mongodb.ObjectID;

const app = express();
const dbURL = process.env.DB_URL || "mongodb://127.0.0.1:27017";
const dbName = process.env.DB_NAME;
const port = process.env.PORT || 3000;
app.use(express.json());
app.use(cors());

app.post("/register", async (req, res) => {
    try {
        let clientInfo = await mongoClient.connect(dbURL);
        let db = clientInfo.db(dbName);
        let result = await db
            .collection("users")
            .findOne({
                email: req.body.email
            });
        if (result) {
            res.status(400).json({
                message: "User already registered"
            });
            clientInfo.close();
        } else {
            let salt = await bcrypt.genSalt(10);
            req.body.password = await bcrypt.hash(req.body.password, salt);
            await db.collection("users").insertOne(req.body);
            res.status(200).json({
                message: "User registered"
            });
            clientInfo.close();
        }
    } catch (error) {
        console.log(error);
    }
});

app.post("/login", async (req, res) => {
    try {
        let clientInfo = await mongoClient.connect(dbURL);
        let db = clientInfo.db(dbName);
        let result = await db
            .collection("users")
            .findOne({
                email: req.body.email
            });
        if (result) {
            let isTrue = await bcrypt.compare(req.body.password, result.password);
            if (isTrue) {
                res.status(200).json({
                    message: "Login success"
                });
            } else {
                res.status(200).json({
                    message: "Login unsuccessful"
                });
            }
        } else {
            res.status(400).json({
                message: "User not registered"
            });
        }
        clientInfo.close();
    } catch (error) {
        console.log(error);
    }
});

app.post("/password/forgot", async (req, res) => {
    try {
        let clientInfo = await mongoClient.connect(dbURL);
        let db = clientInfo.db(dbName);
        let result = await db
            .collection("users")
            .findOne({
                email: req.body.email
            });

        if (result) {
            let transporter = nodemailer.createTransport({
                host: "smtp.gmail.com",
                port: 587,
                secure: false, // true for 465, false for other ports
                auth: {
                    user: process.env.MAIL_USERNAME,
                    pass: process.env.MAIL_PASSWORD,
                },
            });

            // random string
            let str = cryptoRandomString({
                length: 20,
                type: 'url-safe'
            });

            // send mail with defined transport object
            let info = await transporter.sendMail({
                from: `Ibrat Nawaz <${process.env.MAIL_USERNAME}>`, // sender address
                to: `${req.body.email}`, // list of receivers
                subject: `Reset password`, // Subject line
                html: `<b>Click the below link to reset your password. It is one-time link, once you 
                        changed your password using the link, it will br expired.</b><br>
                        <p>http://localhost:8000/reset-password.html?reset_string=${str},user=${req.body.email}</p>`,
            });

            await db.collection("users").updateOne({
                email: req.body.email
            }, {
                $set: {
                    token: str
                }
            })

            res.status(200).json({
                data: {
                    status: "success",
                    message: "Reset password link is sent to your email account."
                }
            });
        } else {
            res.status(400).json({
                data: {
                    status: "failed",
                    message: "No user with this email found. Please provide the registered email. "
                }
            });
        }
        clientInfo.close();
    } catch (error) {
        console.log(error);
        res.status(500).json({
            error
        });
    }
});

app.post("/password/reset", async (req, res) => {
    try {
        let clientInfo = await mongoClient.connect(dbURL);
        let db = clientInfo.db(dbName);
        let result = await db
            .collection("users")
            .findOne({
                $and: [{
                    email: req.body.email
                }, {
                    token: req.body.token
                }]
            });

        if (result) {
            let salt = await bcrypt.genSalt(10);
            let password = await bcrypt.hash(req.body.password, salt);
            await db.collection("users").updateOne({
                email: req.body.email
            }, {
                $set: {
                    token: '',
                    password: password
                }
            })
            res.status(200).json({
                data: {
                    status: 'success',
                    message: 'password changed successfully'
                }
            });
        } else {
            res.status(410).json({
                data: {
                    status: 'failed',
                    message: "page Expired"
                }
            });
        }
        clientInfo.close();
    } catch (error) {
        console.log(error);
    }
})


app.listen(port, () => console.log("your app runs on port:", port));