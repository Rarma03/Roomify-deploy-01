import axios from "axios";
import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import BookingWidget from "../BookingWidget";

export default function SinglePlacePage() {
    const { id } = useParams();
    const [place, setPlace] = useState(null);
    const [showAllPhoto, setShowAllPhoto] = useState(false);

    useEffect(() => {
        if (!id) { return; }
        axios.get(`/places/${id}`).then((res) => {
            setPlace(res.data);
        })
    }, [id])

    if (!place) { return; }

    if (showAllPhoto) {
        return (
            <div className="absolute inset-0 bg-black min-h-screen text-white">
                <h1 className="font-semibold text-center text-2xl mt-10">More Photos of {place.title}</h1>
                <div className="p-8 grid gap-4 bg-black lg:grid-cols-2 items-center">
                    <div>
                        <button className="fixed flex gap-2 text-primary shadow shadow-black rounded-lg px-2 py-1 bg-white right-2 top-2" onClick={() => setShowAllPhoto(false)}>
                            <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="size-6">
                                <path strokeLinecap="round" strokeLinejoin="round" d="m9.75 9.75 4.5 4.5m0-4.5-4.5 4.5M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z" />
                            </svg>
                            Close
                        </button>
                    </div>
                    {place?.photos?.length > 0 && place.photos.map(photo => (
                        <div>
                            <img src={'http://localhost:4000/uploads/' + photo} />
                        </div>
                    ))}
                </div>
            </div>
        );
    }

    return (
        <div className="mt-8 lg:px-[300px]" key={place.Link}>
            <h1 className="text-3xl">{place.title}</h1>
            <a target="_blank" href={"https://maps.google.com/?q=" + place.address} className="text-sm underline flex gap-1 my-2">
                <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="size-6">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M15 10.5a3 3 0 1 1-6 0 3 3 0 0 1 6 0Z" />
                    <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 10.5c0 7.142-7.5 11.25-7.5 11.25S4.5 17.642 4.5 10.5a7.5 7.5 0 1 1 15 0Z" />
                </svg>
                {place.address}
            </a>
            <div className="relative">
                <div className="grid gap-2 grid-cols-[2fr_1fr] rounded-3xl overflow-hidden">
                    <div>
                        {place.photos?.[0] && (
                            <div className="">
                                <img onClick={() => { setShowAllPhoto(true) }} src={'http://localhost:4000/uploads/' + place.photos[0]} className="aspect-square object-cover w-full h-full" />
                            </div>
                        )}
                    </div>
                    <div className="grid">
                        {place.photos?.[1] && (
                            <img onClick={() => { setShowAllPhoto(true) }} src={'http://localhost:4000/uploads/' + place.photos[1]} className="aspect-square object-cover" />
                        )}
                        <div className="overflow-hidden">
                            {place.photos?.[2] && (
                                <img onClick={() => { setShowAllPhoto(true) }} src={'http://localhost:4000/uploads/' + place.photos[2]} className="aspect-square object-cover relative top-2" />
                            )}
                        </div>
                    </div>
                </div>
                <button onClick={(() => { setShowAllPhoto(true); })} className="absolute text-white bottom-2 right-2 bg-primary rounded-lg flex text-sm items-center p-0.5 opacity-80 gap-1">
                    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="size-6">
                        <path strokeLinecap="round" strokeLinejoin="round" d="M8.625 12a.375.375 0 1 1-.75 0 .375.375 0 0 1 .75 0Zm0 0H8.25m4.125 0a.375.375 0 1 1-.75 0 .375.375 0 0 1 .75 0Zm0 0H12m4.125 0a.375.375 0 1 1-.75 0 .375.375 0 0 1 .75 0Zm0 0h-.375M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z" />
                    </svg>
                    <p>Show more Photos</p>
                </button >
            </div>

            <div className="grid gap-8 grid-cols-1 sm:grid-cols-[2fr_1fr]">
                <div>
                    <div className="my-4">
                        <h2 className="font-semibold text-1xl">About the Place</h2>
                        {place.description}
                    </div>
                    <b>Check In: </b>{place.checkIn}<br />
                    <b>Check In: </b>{place.checkOut}<br />
                    <b>Max Guest: </b>{place.maxGuests}
                </div>
                <BookingWidget place={place} />
            </div>
            <div>
                <h2 className="font-semibold text-1xl mt-5">Extra Info</h2>
            </div>
            <div className="text-sm text-gray-700 leading-4 mb-4 mt-1">
                {place.extraInfo}
            </div>
        </div >
    );
}