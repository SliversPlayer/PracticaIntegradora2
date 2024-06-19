import passport from "passport";
import local from 'passport-local';
import GitHubStrategy from 'passport-github2';
import usersModel from '../models/user.model.js';
import { createHash, isValidPassword } from "../utils.js";
import jwt from 'passport-jwt';
import jwtLibrary from 'jsonwebtoken'; // Importar jsonwebtoken para generar tokens
import dotenv from 'dotenv';
// Cargar variables de entorno
dotenv.config();

const JWTStrategy = jwt.Strategy;
const ExtractJWT = jwt.ExtractJwt;
const userService = usersModel;
const LocalStrategy = local.Strategy;

const cookieExtractor = (req) => {
    let token = null;
    if (req && req.cookies) {
        token = req.cookies['coderCookieToken'];
    }
    return token;
};

const initializePassport = () => {
    
    // Estrategia JWT
    passport.use('jwt', new JWTStrategy({
        jwtFromRequest: ExtractJWT.fromExtractors([cookieExtractor]),
        secretOrKey: "coderSecret"
        }, async (jwt_payload, done) => {
        try {
            return done(null, jwt_payload)  
        }
         catch (error) {
            return done(error);
        }
    }));

    // Serializar y deserializar
    passport.serializeUser((user, done) => {
        done(null, user._id);
    });

    passport.deserializeUser(async (id, done) => {
        let user = await userService.findById(id);
        done(null, user);
    });

    // Estrategia de registro local
    passport.use('register', new LocalStrategy(
        { passReqToCallback: true, usernameField: 'email' },
        async (req, username, password, done) => {
            const { first_name, last_name, email, age } = req.body;
            try {
                let user = await userService.findOne({ email: username });
                if (user) {
                    console.log("El usuario ya existe");
                    return done(null, false);
                }
                const newUser = {
                    first_name,
                    last_name,
                    email,
                    age,
                    password: createHash(password)
                };
                let result = await userService.create(newUser);
                return done(null, result);
            } catch (error) {
                return done("Error al obtener el suuario" + error);
            }
        }
    ));

    // Estrategia de inicio de sesión local
    passport.use('login', new LocalStrategy({ usernameField: 'email' }, async (username, password, done) => {
        try {
            const user = await userService.findOne({ email: username });
            if (!user) {
                console.log("El usuario no existe");
                return done(null, false);
            }
            if (!isValidPassword(user, password)) {
                return done(null, false);
            }
            // Generar JWT
            const token = jwtLibrary.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
            return done(null, { user, token });
        } catch (error) {
            return done(error);
        }
    }));

    // Estrategia de GitHub
    passport.use('github', new GitHubStrategy({
        clientID: process.env.GITHUB_CLIENT_ID,
        clientSecret: process.env.GITHUB_CLIENT_SECRET,
        callbackURL: process.env.GITHUB_CALLBACK_URL,
    }, async (accessToken, refreshToken, profile, done) => {
        try {
            console.log(profile);
            let user = await userService.findOne({ email: profile._json.email });
            if (!user) {
                let newUser = {
                    first_name: profile._json.name,
                    last_name: "",
                    age: 89,
                    email: profile._json.email,
                    password: ""
                };
                let result = await userService.create(newUser);
                // Generar JWT
                const token = jwtLibrary.sign({ id: result._id, email: result.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
                return done(null, { user: result, token });
            } else {
                // Generar JWT
                const token = jwtLibrary.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
                return done(null, { user, token });
            }
        } catch (error) {
            return done(error);
        }
    }));



};

export default initializePassport;



//     passport.use('github', new GitHubStrategy({

//         clientID: process.env.GITHUB_CLIENT_ID,
//         clientSecret: process.env.GITHUB_CLIENT_SECRET,
//         callbackURL: process.env.GITHUB_CALLBACK_URL,
        
//     }, async(accessToken, refreshToken, profile, done)=>{
//         try {
//             console.log(profile);
//             let user = await userService.findOne({email: profile._json.email})
//             if(!user){
//                 let newUser={
//                     first_name:profile._json.name,
//                     last_name:"",
//                     age: 89,
//                     email:profile._json.email,
//                     password:""
//                 }
//                 let result = await userService.create(newUser)
//                 done(null,user)
//             }
//             else{
//                 done(null,user)
//             }
//         } catch (error) {
//             return done(error)
//         }
//     }
// ))