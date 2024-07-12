import axios from "axios"
import { useEffect, useState } from "react"
import { Link } from "react-router-dom";

export default function IndexPage() {
    const [places, setPlaces] = useState([]);
    useEffect(() => {
        axios.get('/places').then((res) => {
            // setPlaces([...res.data, ...res.data]);
            setPlaces(res.data);
        })
    }, []);
    return (
        <>
            <div className="border mt-10"></div>
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-x-6 gap-y-8 mt-5">
                {places.length > 0 && places.map(place => (
                    <Link to={'/place/' + place._id} key={place._id} className="mt-4">
                        {place.photos?.[0] && (
                            <div className="bg-gray-500 rounded-2xl flex mb-2">
                                <img src={'http://localhost:4000/uploads/' + place.photos[0]} className="rounded-2xl aspect-square object-cover w-full h-full" />
                            </div>
                        )}
                        <h2 className="truncate font-bold">
                            {place.address}
                        </h2>
                        <h3 className="text-sm truncate text-gray-500">
                            {place.title}
                        </h3>
                        <div className="mt-1">
                            <span className="font-bold">
                                &#8377; {place.price} per night
                            </span>
                        </div>
                    </Link>
                ))}
            </div>
        </>
    )
}