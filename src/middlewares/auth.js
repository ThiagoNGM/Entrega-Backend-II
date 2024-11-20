import express from 'express';

export const isLoggedIn = (req, res, next) => {
    const token = req.cookies['cookieToken'];
    if (!token) return res.redirect('/login');

    jwt.verify(token, process.env.PRIVATEKEYJWT, (err, decoded) => {
        if (err) return res.redirect('/login');
        req.user = decoded; // Establecer la información de usuario
        next();
    });
};

export const isLoggedOut = (req, res, next) => {
    if (req.session.user) {
        res.redirect('/current');
    } else {
        next();
    }
}
