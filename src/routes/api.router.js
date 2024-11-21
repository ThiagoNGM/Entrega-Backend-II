import express, { Router } from 'express';
import UserService from '../models/user.models.js';
import { generateToken, isValidPassword, authToken } from '../utils.js';

const router = express.Router();

router.post('/register', async (req, res) => {
    try {
        const newUser = new UserService(req.body);
        await newUser.save();
        res.json({ message: 'Usuario registrado con éxito' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

router.post('/login', async (req, res) => {
    try {
        const user = await UserService.findOne({ email: req.body.email });
        if (!user) {
            console.log('Usuario no encontrado'); // Depuración
            return res.status(400).json({ error: 'Credenciales inválidas' });
        }

        if (!isValidPassword(user, req.body.password)) {
            console.log('Contraseña incorrecta'); // Depuración
            return res.status(400).json({ error: 'Credenciales inválidas' });
        }

        const token = generateToken({ userId: user._id, role: user.role });
        res.cookie('currentUser', token, { httpOnly: true });
        res.json({ message: 'Inicio de sesión exitoso' });

    } catch (error) {
        console.error('Error en el login:', error); // Depuración
        res.status(500).json({ error: error.message });
    }
});



router.get('/current', authToken, (req, res) => {
    const user = req.user;
    res.json({ currentUser: user });
});

export default router;