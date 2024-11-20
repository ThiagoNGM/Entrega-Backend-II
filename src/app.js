import express from 'express';
import { generateToken, authToken, passportCall, roleAuthorization } from './utils.js';
import cookieParser from 'cookie-parser';
import handlebars from 'express-handlebars';
import { __dirname } from './utils.js';
import dotenv from "dotenv";
import session from 'express-session';
import mongoose from 'mongoose'
import userRouter from './routes/user.router.js'
import apiRouter from './routes/api.router.js'
import jwt from 'jsonwebtoken';
import initializePassport from './config/passport.config.js';
import passport from 'passport';


initializePassport();

const app = express();

dotenv.config();

const uriMongo = process.env.URIMONGO;
const PORT = process.env.PORT || 8080;
const firmacookie = process.env.FIRMACOOKIE

app.use(express.json())
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser(firmacookie));
app.use(express.static(__dirname + '/public'));
app.use(passport.initialize());

app.engine('handlebars', handlebars.engine());
app.set('views', __dirname + '/views');
app.set('view engine', 'handlebars');

mongoose.connect(uriMongo)
    .then(() => console.log('Conectado a MongoDB'))
    .catch((error) => console.log('Error en la conexión:', error));


const PRIVATE_KEY = process.env.PRIVATEKEYJWT;

app.use('/users', userRouter);
app.use('/api/sesions', apiRouter);

app.post('/login', (req, res) => {
    const { email, password } = req.body;

    if (email === req.body.email && password === req.body.password) {
        let token = jwt.sign({ email, password, role: "user" }, firmacookie, { expiresIn: "24hr" });
        res.cookie('cookieToken', token, { maxAge: 60 * 60 * 1000, httpOnly: true }).send({ message: "sesión iniciada" });
    } else {
        res.status(401).send({ message: "credenciales inválidas" });
    }
});


app.get('/current', passportCall('jwt'), roleAuthorization('admin'), (req, res) => {
    res.send(req.user);
});

app.listen(PORT, () => console.log('lisntening on port: ' + PORT))

