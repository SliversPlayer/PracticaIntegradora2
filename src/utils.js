import { fileURLToPath } from 'url';
import { dirname } from 'path';
import bcrypt from 'bcryptjs';
import passport from 'passport';

// Funciones para crear y validar hash de contraseñas
export const createHash = password => bcrypt.hashSync(password, bcrypt.genSaltSync(10));
export const isValidPassword = (user, password) => bcrypt.compareSync(password, user.password);

// __filename and __dirname aren't disponibles por defecto en ES modules, por lo que necesitamos crearlos
const __filename = fileURLToPath(import.meta.url);
export const __dirname = dirname(__filename);

// Middleware para manejar estrategias de Passport
export const passportCall = (strategy) => {
    return async (req, res, next) => {
        passport.authenticate(strategy, function (err, user, info) {
            if (err) {
                return next(err);
            }
            if (!user) {
                // Verificar si info es undefined y manejar el mensaje de error adecuadamente
                const errorMessage = info ? (info.message || info.toString()) : 'Authentication failed';
                return res.status(401).send({ error: errorMessage });
            }
            req.user = user;
            next();
        })(req, res, next);
    };
};

// Middleware para manejar autorización basada en roles
export const authorization = (role) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).send({ error: "Unauthorized" });
        }
        if (req.user.role !== role) {
            return res.status(403).send({ error: "No permission" });
        }
        next();
    };
};
