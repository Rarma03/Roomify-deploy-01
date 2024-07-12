import { useEffect, useState } from 'react';
import AccountNav from '../AccountNav'
import axios from 'axios';
import { format } from 'date-fns'
import BookingDates from '../BookingDates';
import { Link } from 'react-router-dom';

export default function BookingPage() {
    const [bookings, setBookings] = useState([]);
    useEffect(() => {
        axios.get('/bookings').then(res => {
            setBookings(res.data);
        })
    }, [])
    return (
        <div className='' >
            <AccountNav />
            <div className=''>
                {bookings?.length > 0 && bookings.map(booking => (
                    <Link to={`/account/bookings/${booking._id}`}
                        className='flex gap-4 bg-gray-200 rounded-2xl overflow-hidden mt-5 justify-around md:text-xl'>
                        <div className='aspect-square sm:h-[300px]'>
                            {booking.place.photos.length > 0 && (
                                <img className='w-full h-full object-cover' src={'http://localhost:4000/uploads/' + booking.place.photos[0]} alt='no image' />
                            )}
                        </div>
                        <div className='flex items-center'>
                            <div className='py-3 shrink grow-0'>
                                <h2 className='font-semibold'>{booking.place.title}</h2>
                                <BookingDates booking={booking} className='mt-3' />
                                <div className="flex gap-1 mt-3">
                                    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="size-6">
                                        <path strokeLinecap="round" strokeLinejoin="round" d="M2.25 8.25h19.5M2.25 9h19.5m-16.5 5.25h6m-6 2.25h3m-3.75 3h15a2.25 2.25 0 0 0 2.25-2.25V6.75A2.25 2.25 0 0 0 19.5 4.5h-15a2.25 2.25 0 0 0-2.25 2.25v10.5A2.25 2.25 0 0 0 4.5 19.5Z" />
                                    </svg>

                                    <div className=''>Total price :
                                        <span className='bg-primary bg-opacity-80 rounded-lg p-1 text-white'>
                                            &#8377; {booking.price}
                                        </span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </Link>
                ))}
            </div>
        </div >
    );
}