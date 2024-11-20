import { fileURLToPath } from 'url';
import path from 'path';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import dotenv from 'dotenv';
import passport from 'passport';
dotenv.config();

const PRIVATE_KEY = process.env.PRIVATEKEYJWT;

export const generateToken = (user) => {
    const token = jwt.sign(user, PRIVATE_KEY, { expiresIn: '24hr' });
    return token;
};

export const authToken = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).send({
        error: "No autenticado"
    });

    const token = authHeader.split(' ')[1];
    jwt.verify(token, PRIVATE_KEY, (error, credentials) => {
        if (error) return res.status(403).send({ error: "No autorizado" });
        req.user = credentials.user;
        next();
    });
};

export const passportCall = (strategy) => {
    return async (req, res, next) => {
        passport.authenticate(strategy, function (err, user, info) {
            if (err) return next(err);
            if (!user) {
                return res.status(401).send({ error: info.messages ? info.messages : info.toString() });
            }
            req.user = user;
            next();
        })(req, res, next);
    };
};

export const roleAuthorization = (role) => {
    return async (req, res, next) => {
        if (!req.user) return res.status(401).send({ message: 'No autorizado' });
        if (req.user.role != role)
            return res.status(403).send({ error: "sin permisos" });
        next();
    }
};

export const createHash = (password) => bcrypt.hashSync(password, bcrypt.genSaltSync(10));

export const isValidPassword = (user, password) => bcrypt.compareSync(password, user.password);

const __filename = fileURLToPath(import.meta.url);
export const __dirname = path.dirname(__filename);
