import mongoose from "mongoose";

const placeSchema = new mongoose.Schema({
    owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    title: String,
    address: String,
    photos: [String],
    description: String,
    perks: [String],
    extraInfo: String,
    checkIn: Number,
    checkOut: Number,
    maxGuests: Number,
    price: Number
})
const PlaceModel = mongoose.model('Places', placeSchema);
// module.exports = UserModel; // old way
export default PlaceModel;