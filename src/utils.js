import { fileURLToPath } from 'url';
import { dirname } from 'path';
import bcrypt from 'bcryptjs'
import passport from 'passport'
import { error } from 'console';

export const createHash = password => bcrypt.hashSync(password, bcrypt.genSaltSync(10))

export const isValidPassword = (user, password) => bcrypt.compareSync(password, user.password)

// __filename and __dirname aren't available by default in ES modules, so we need to create them
const __filename = fileURLToPath(import.meta.url);
export const __dirname = dirname(__filename);

export const passportCall = (strategy) => {
    return async ( req,res,next) => {
    passport.authenticate(strategy, function (err,user,info) {
        if(err) {
            return nextTick(err)
        }
        if (!user) {
            return res.status(401).send({ error:info.messages ? info.messages : info.toString() })
        }
        req.user = usernext()
    })
        (req, res, next)
    }
}
export const authorization = (role) => {
    return async (req, res, next) => {
        if (!req.user) return res.status(401).send({ error: "Unauthorized"})
        if (req.user.role !== role) return res.status(403).send({error: "No permission"})
            next()
    }
}
