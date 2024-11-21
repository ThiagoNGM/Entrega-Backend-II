import express from "express";
import { authToken } from "../utils.js";

const router = express.Router();

router.get('/login', (req, res) => {
    res.render('login', { currentUser: req.cookies.currentUser })
})

router.get('/current', authToken, (req, res) => {
    const user = req.user;
    res.render('current', { currentUser: user });
})

export default router;