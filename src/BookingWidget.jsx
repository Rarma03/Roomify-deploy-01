import { useState } from "react";
import { differenceInCalendarDays } from "date-fns";
import axios from "axios";
import { Navigate } from "react-router-dom";

export default function BookingWidget({ place }) {
    const [checkIn, setCheckIn] = useState('');
    const [checkOut, setCheckOut] = useState('');
    const [numberOfGuest, setNumberOfGuest] = useState(1);
    const [phone, setPhone] = useState('');
    const [fullName, setFullName] = useState('');
    const [redirect, setRedirect] = useState('');

    const calculateDays = () => {
        if (checkIn.length > 0 && checkOut.length > 0) {
            const diff = differenceInCalendarDays(new Date(checkOut), new Date(checkIn));
            return diff > 0 ? diff : 0; // Ensure positive day difference
        }
        return 0;
    };

    async function bookThisPlace() {
        const data = {
            checkIn, checkOut, numberOfGuest, fullName, phone, place: place._id,
            price: calculateDays() * place.price * numberOfGuest
        };
        const res = await axios.post('/bookings', data);

        const bookingId = res.data._id;
        setRedirect(`/account/bookings/${bookingId}`);
    }

    if (redirect) {
        return <Navigate to={redirect} />
    }

    return (
        <div className="bg-white p-4 rounded-2xl shadow mt-8 h-fit">
            <div className="text-center font-semibold">
                Price: &#8377; {place.price} / per night
            </div>
            <div className="border rounded-2xl mt-4 text-xs md:text-base">
                <div className="flex ">
                    <div className="px-4 py-3">
                        <label>Check-In: </label>
                        <input type="date"
                            value={checkIn}
                            onChange={ev => setCheckIn(ev.target.value)} />
                    </div>
                    <div className="px-4 py-3 border-l">
                        <label>Check-Out: </label>
                        <input type="date"
                            value={checkOut}
                            onChange={ev => setCheckOut(ev.target.value)} />
                    </div>
                </div>
                <div className="px-4 py-3 border-t">
                    <label>Guest Count : </label>
                    <input type="number" placeholder="1"
                        value={numberOfGuest}
                        onChange={ev => setNumberOfGuest(ev.target.value)} />
                </div>
                {checkIn.length > 0 && checkOut.length > 0 && (
                    <div className="px-4 py-3 border-t">
                        <label>Full Name : </label>
                        <input type="string" placeholder="1"
                            value={fullName}
                            onChange={ev => setFullName(ev.target.value)} />
                        <label>Phone No. : </label>
                        <input type="string" placeholder="1"
                            value={phone}
                            onChange={ev => setPhone(ev.target.value)} />
                    </div>
                )}
            </div>
            <button className="mt-4 bg-primary p-2 w-full text-white rounded-2xl hover:bg-sky-700 hover:shadow-xl cursor-pointer" onClick={bookThisPlace}>
                Book
                {checkIn.length > 0 && checkOut.length > 0 && (
                    <span>
                        &nbsp;for {calculateDays()} days
                    </span>
                )}
            </button>
            <h2>
                {checkIn.length > 0 && checkOut.length > 0 && (
                    <span>
                        Total Amount : {calculateDays() * place.price * numberOfGuest} &#8377;
                    </span>
                )}
            </h2>
        </div>
    );
}
