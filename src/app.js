import express from 'express';
import handlebars from 'express-handlebars';
//import session from 'express-session';
import MongoStore from 'connect-mongo';
import mongoose from 'mongoose';
import path from 'path';
import { __dirname, authorization, passportCall } from './utils.js';
import { Server } from 'socket.io';
import passport from 'passport';
import initializePassport from './config/passport.config.js';
import dotenv from 'dotenv';
// Importa tus routers y otros módulos necesarios
import productsRouter from '../src/routes/products.router.js';
import cartsRouter from '../src/routes/carts.router.js';
import messagesRouter from '../src/routes/messages.router.js';
import viewsRouter from '../src/routes/views.router.js';
import socketProducts from './listener/socketProducts.js';
import sessionsRouter from './routes/api/sessions.js';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';



// Cargar variables de entorno
dotenv.config();
const app = express();
const PORT = process.env.PORT || 8080;

// Variables de conexión
const conString = process.env.MONGO_URI;

// Conexión a MongoDB
mongoose.connect(conString, {
}).then(() => {
    console.log('Conectado a MongoDB');
}).catch((error) => {
    console.error('Error conectándose a MongoDB', error);
});

// Configuración de archivos estáticos
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.static(__dirname + "/src/public"));

// Configuración de Handlebars
app.engine('handlebars', handlebars.engine());
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'handlebars');

// Middleware
app.use(express.static('public'))
app.use(express.json());
app.use(cookieParser())
initializePassport()
app.use(passport.initialize())

app.use(express.urlencoded({ extended: true }));

// Middleware para manejar las rutas
app.use('/', viewsRouter);
app.use('/api/messages', messagesRouter);
app.use('/api/products', productsRouter);
app.use('/api/carts', cartsRouter);
app.use('/api/sessions', sessionsRouter);

app.post('/login', (req, res) => {
    const {email, password} = req.body
    if (email == "coder@coder.com" && password == "coderpass") {
        let token = jwt.sign({ email, password, role: "user"}, "coderSecret", {expiresIn: "24h"})
        res.send({ message: "inicio de sesión exitoso", token})
    }
})

app.get('/current', passportCall('jwt'), authorization('user'), (req,res) => {
    res.send(req.user);
})

const httpServer = app.listen(PORT, () => {
    try {
        console.log(`Listening to the port ${PORT}\nAcceder a:`);
        console.log(`\t1). http://localhost:${PORT}/api/products`);
        console.log(`\t2). http://localhost:${PORT}/api/messages`);
        console.log(`\t3). http://localhost:${PORT}/login`);
    } catch (err) {
        console.log(err);
    }
});

const socketServer = new Server(httpServer);
socketProducts(socketServer);
