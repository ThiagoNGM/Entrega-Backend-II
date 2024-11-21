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

export const isValidPassword = (user, password) => {
    console.log("Contraseña ingresada: ", password);
    console.log("Hash en base de datos: ", user.password);

    const isMatch = bcrypt.compareSync(password, user.password);
    console.log("¿Las contraseñas coinciden?", isMatch);

    return isMatch;
};

export const login = (req, res) => {
    const { email, password } = req.body;

    User.findOne({ email }, (err, user) => {
        if (err || !user) {
            return res.status(400).json({ error: 'Credenciales inválidas' });
        }

        if (!isValidPassword(user, password)) {
            console.log('Contraseña ingresada:', password);
            console.log('Contraseña en base de datos:', user.password);
            return res.status(400).json({ error: 'Credenciales inválidas' });
        }

        const token = generateToken(user);
        res.json({ message: 'Login exitoso', token });
    });
};

export const generateNewHash = (password) => {
    bcrypt.hash(password, 10, (err, hash) => {
        if (err) throw err;
        console.log("Nuevo hash generado: ", hash);
    });
};

const __filename = fileURLToPath(import.meta.url);
export const __dirname = path.dirname(__filename);
