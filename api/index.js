import express from 'express';
import cors from 'cors';
import mongoose from 'mongoose';
import 'dotenv/config';
import bcrypt from 'bcryptjs';
import User from './models/User.js';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import imageDownloader from 'image-downloader';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import multer from 'multer';
import fs from 'fs';
import Place from './models/Places.js';
import axios from 'axios';
import Booking from './models/Booking.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();

// basically the secret means key through which key password is hashed  
const bcryptSalt = bcrypt.genSaltSync(10);
const jwtSecret = "ajlj3342nowpqpn453908";

app.use(express.json());
app.use(cookieParser());

// this is done to make photo visible at placeForm page
app.use('/uploads', express.static(__dirname + '/uploads'))

app.use(cors({
    credentials: true,
    origin: ['http://localhost:3000', 'http://192.168.1.4:3000']
}));

mongoose.connect(process.env.MONGO_URL);

app.get('/', (req, res) => {
    res.json('test okay');
});

app.post('/register', async (req, res) => {
    const { name, email, password } = req.body;
    try {
        const userDoc = await User.create({
            name,
            email,
            password: bcrypt.hashSync(password, bcryptSalt)
        });

        res.json(userDoc);
    } catch (e) {
        res.status(400).json(e);
    }
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const userDoc = await User.findOne({ email });
        if (userDoc) {
            const isPasswordValid = bcrypt.compareSync(password, userDoc.password);
            if (isPasswordValid) {
                jwt.sign({ email: userDoc.email, name: userDoc.name, id: userDoc._id }, jwtSecret, {}, (err, token) => {
                    if (err) throw err;
                    res.cookie('token', token, {}).json(userDoc);
                });
            } else {
                res.status(400).json({ error: "Invalid password" });
            }
        } else {
            res.status(400).json({ error: "User not found" });
        }
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
})

app.get('/profile', (req, res) => {
    const { token } = req.cookies;
    if (token) {
        jwt.verify(token, jwtSecret, {}, (err, user) => {
            if (err) throw err;
            res.json(user);
        })
    }
    else {
        res.json(null);
    }
    res.json({ token });
})


app.post('/logout', (req, res) => {
    res.cookie('token', '').json(true);
})

// console.log({ __dirname });
function isValidUrl(url) {
    try {
        new URL(url);
        return true;
    } catch (_) {
        return false;
    }
}

app.post('/upload-by-link', async (req, res) => {
    const { link } = req.body;

    if (!link || !isValidUrl(link)) {
        return res.status(400).json({ error: 'Invalid URL' });
    }

    const newName = 'photo-' + Date.now() + '.jpg';
    const destPath = __dirname + '/uploads/' + newName; // Fixed path concatenation

    try {
        await imageDownloader.image({
            url: link,
            dest: destPath
        });

        res.json(newName); // Sending just the filename back to the client
    } catch (error) {
        console.error('Error downloading image:', error);
        res.status(500).json({ error: 'Failed to download image' });
    }
});

const photosMiddleware = multer({ dest: 'uploads/' });
app.post('/upload', photosMiddleware.array('photos', 100), (req, res) => {
    const uploadedFiles = [];
    for (let i = 0; i < req.files.length; i++) {
        const { path, originalname } = req.files[i];
        const parts = originalname.split('.');
        const extension = parts[parts.length - 1];
        // console.log(path);
        const newPath = path + '.' + extension;
        // console.log(newPath);
        fs.renameSync(path, newPath);
        // Ensure path normalization
        uploadedFiles.push(newPath.replace('uploads', '').replace(/\\/g, '/'));
    }
    res.json(uploadedFiles);
});


app.post('/places', (req, res) => {
    const { token } = req.cookies;

    jwt.verify(token, jwtSecret, {}, async (err, user) => {
        if (err) {
            console.error('JWT verification failed:', err);
            return res.status(401).json({ error: 'Unauthorized' });
        }

        const { title, address, addedPhotos, description, perks, extraInfo, checkIn, checkOut, maxGuests, price } = req.body;

        if (!title || !address || !description) {
            alert('required field missing !!');
            return res.status(400).json({ error: 'Missing required fields' });
        }

        try {
            const placeDoc = await Place.create({
                owner: user.id,
                title,
                address,
                photos: addedPhotos,
                description,
                perks,
                extraInfo,
                checkIn,
                checkOut,
                maxGuests,
                price
            });
            res.json(placeDoc);
        } catch (error) {
            console.error('Error creating place:', error);
            res.status(500).json({ error: 'Internal server error' });
        }
    });
});

app.get('/places', async (req, res) => {
    res.json(await Place.find());
})

app.get('/user-places', (req, res) => {
    const { token } = req.cookies;

    jwt.verify(token, jwtSecret, {}, async (err, user) => {
        if (err) {
            console.error('JWT verification failed:', err);
            return res.status(401).json({ error: 'Unauthorized' });
        }

        const { id } = user;

        try {
            const places = await Place.find({ owner: id });
            res.json(places);
        } catch (error) {
            console.error('Error fetching places:', error);
            res.status(500).json({ error: 'Internal server error' });
        }
    });
});

app.get('/places/:id', async (req, res) => {
    const { id } = req.params;
    res.json(await Place.findById(id));
})



app.put('/places/:id', async (req, res) => {
    const { token } = req.cookies;
    const { id } = req.params;
    const { title, address, addedPhotos, description, perks, extraInfo, checkIn, checkOut, maxGuests, price } = req.body;

    jwt.verify(token, jwtSecret, {}, async (err, user) => {
        if (err) {
            console.error('JWT verification failed:', err);
            return res.status(401).json({ error: 'Unauthorized' });
        }

        try {
            const placeDoc = await Place.findById(id);

            if (!placeDoc) {
                return res.status(404).json({ error: 'Place not found' });
            }

            if (user.id !== placeDoc.owner.toString()) {
                return res.status(403).json({ error: 'Forbidden' });
            }

            placeDoc.set({
                title,
                address,
                photos: addedPhotos,
                description,
                perks,
                extraInfo,
                checkIn,
                checkOut,
                maxGuests,
                price
            });

            await placeDoc.save();
            res.json('okay');
        } catch (error) {
            console.error('Error updating place:', error);
            res.status(500).json({ error: 'Internal server error' });
        }
    });
});


function getUserDataFromReq(req) {
    return new Promise((resolve, reject) => {
        jwt.verify(req.cookies.token, jwtSecret, {}, (err, user) => {
            if (err) return reject(err);  // Correctly reject on error
            resolve(user);
        });
    });
}

app.post('/bookings', async (req, res) => {
    const { checkIn, checkOut, numberOfGuest, fullName, phone, price, place } = req.body; // Destructure the necessary fields

    try {
        const userData = await getUserDataFromReq(req); // Assuming getUserDataFromReq should be getUserDataFromToken

        const booking = await Booking.create({
            checkIn, checkOut, numberOfGuest, fullName, phone, price, place,
            user: userData.id
        });

        res.json(booking);
    } catch (err) {
        res.status(500).json({ error: 'Failed to create booking', details: err.message });
    }
});

app.get('/bookings', async (req, res) => {
    const userData = await getUserDataFromReq(req);
    res.json(await Booking.find({ user: userData.id }).populate('place'))
})


if (process.env.PORT) {
    app.listen(process.env.PORT);
}