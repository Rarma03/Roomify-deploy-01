import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import AccountNav from '../AccountNav';
import axios from 'axios';

export default function PlacesPage() {
    const [places, setPlaces] = useState([]);

    useEffect(() => {
        axios.get('/user-places')
            .then(({ data }) => {
                setPlaces(data);
            })
            .catch(error => {
                console.error('Error fetching places:', error);
            });
    }, []);

    return (
        <div>
            <AccountNav />
            <div className="text-center mt-4">
                <Link className='bg-primary text-center rounded-full px-6 py-2 gap-1 inline-flex text-white mt-5' to={'/account/places/new'}>
                    Add New Place +
                </Link>
            </div>
            <div className='mt-4'>
                {places.length > 0 ? (
                    places.map(place => (
                        <Link to={'/account/places/' + place._id} key={place._id} className='bg-gray-100 p-2 rounded-xl mt-2 flex gap-4 cursor-pointer'>
                            {/* you havent added grow and shrink property as in tutorial */}
                            <div className='flex w-32 h-32 bg-gray-300 shrink-0'>
                                {place.photos.length > 0 && (
                                    <img className='w-full h-full object-cover' src={'http://localhost:4000/uploads/' + place.photos[0]} alt='no image' />
                                )}
                            </div>
                            <div className='shrink grow-0'>
                                <h2 className='text-xl'>
                                    {place.title}
                                </h2>
                                <p className='text-sm mt-2 '>
                                    {place.description}
                                </p>
                            </div>
                        </Link>
                    ))
                ) : (
                    <p>No places found.</p>
                )}
            </div>
        </div>
    );
}
