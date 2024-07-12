import axios from 'axios';
import { useState } from 'react';

export default function PhotoUploader({ addedPhotos, onChange }) {
    const [photoLink, setPhotoLink] = useState('');

    async function addPhotoByLink(ev) {
        ev.preventDefault();
        try {
            const { data } = await axios.post('/upload-by-link', {
                link: photoLink
            });
            onChange([...addedPhotos, data]);
            setPhotoLink('');
        } catch (error) {
            console.error("Error uploading photo by link:", error);
        }
    }
    async function uploadPhoto(ev) {
        const files = ev.target.files;
        const data = new FormData();
        for (let i = 0; i < files.length; i++) {
            data.append('photos', files[i]);
        }
        try {
            const { data: filenames } = await axios.post('/upload', data, {
                headers: { 'Content-Type': 'multipart/form-data' }
            });
            onChange([...addedPhotos, ...filenames]);
        } catch (error) {
            console.error("Error uploading files:", error);
        }
    }

    function removePhoto(filename) {
        // Create a new array excluding the filename to be removed
        const newAddedPhotos = addedPhotos.filter(photo => photo !== filename);

        // If the removed photo is the lead photo, select a new lead photo
        if (filename === addedPhotos[0] && newAddedPhotos.length > 0) {
            selectAsMainPhoto(null, newAddedPhotos[0], newAddedPhotos);
        } else {
            onChange(newAddedPhotos);
        }
    }

    function selectAsMainPhoto(ev, filename, photos = addedPhotos) {
        if (ev) {
            ev.preventDefault();
        }
        // Create a new array excluding the selected photo
        const addedPhotoWithoutSelected = photos.filter(photo => photo !== filename);

        // Add the selected photo at the beginning of the array
        const newAddedPhotos = [filename, ...addedPhotoWithoutSelected];

        onChange(newAddedPhotos);
    }

    return (
        <>
            <div className='flex gap-2'>
                <input
                    type="text"
                    placeholder='Add using a link ...jpg'
                    value={photoLink}
                    onChange={ev => setPhotoLink(ev.target.value)}
                />
                <button
                    className='bg-gray-200 px-4 rounded-2xl grow'
                    onClick={addPhotoByLink}
                >
                    Add&nbsp;Photo
                </button>
            </div>
            <div className='mt-2 grid grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-2'>
                {addedPhotos.length > 0 && addedPhotos.map(link => (
                    <div className='h-32 flex relative' key={link}>
                        <img className='rounded-xl w-full object-cover ' src={'http://localhost:4000/uploads/' + link}></img>
                        <button className='absolute bottom-2 right-2 text-white bg-primary rounded-xl p-0.5 bg-opacity-80 cursor-pointer' onClick={() => removePhoto(link)}>
                            <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="size-6">
                                <path strokeLinecap="round" strokeLinejoin="round" d="m14.74 9-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 0 1-2.244 2.077H8.084a2.25 2.25 0 0 1-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 0 0-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 0 1 3.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 0 0-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 0 0-7.5 0" />
                            </svg>

                        </button>
                        <button className='absolute top-2 left-2 text-white rounded-xl p-0.5  cursor-pointer' onClick={(ev) => selectAsMainPhoto(ev, link)}>
                            {link === addedPhotos[0] && (
                                <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="size-6 bg-primary rounded-md bg-opacity-90">
                                    <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75 11.25 15 15 9.75M21 12c0 1.268-.63 2.39-1.593 3.068a3.745 3.745 0 0 1-1.043 3.296 3.745 3.745 0 0 1-3.296 1.043A3.745 3.745 0 0 1 12 21c-1.268 0-2.39-.63-3.068-1.593a3.746 3.746 0 0 1-3.296-1.043 3.745 3.745 0 0 1-1.043-3.296A3.745 3.745 0 0 1 3 12c0-1.268.63-2.39 1.593-3.068a3.745 3.745 0 0 1 1.043-3.296 3.746 3.746 0 0 1 3.296-1.043A3.746 3.746 0 0 1 12 3c1.268 0 2.39.63 3.068 1.593a3.746 3.746 0 0 1 3.296 1.043 3.746 3.746 0 0 1 1.043 3.296A3.745 3.745 0 0 1 21 12Z" />
                                </svg>
                            )}
                            {link !== addedPhotos[0] && (

                                <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="size-6 bg-black rounded-md bg-opacity-70">
                                    <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75 11.25 15 15 9.75M21 12c0 1.268-.63 2.39-1.593 3.068a3.745 3.745 0 0 1-1.043 3.296 3.745 3.745 0 0 1-3.296 1.043A3.745 3.745 0 0 1 12 21c-1.268 0-2.39-.63-3.068-1.593a3.746 3.746 0 0 1-3.296-1.043 3.745 3.745 0 0 1-1.043-3.296A3.745 3.745 0 0 1 3 12c0-1.268.63-2.39 1.593-3.068a3.745 3.745 0 0 1 1.043-3.296 3.746 3.746 0 0 1 3.296-1.043A3.746 3.746 0 0 1 12 3c1.268 0 2.39.63 3.068 1.593a3.746 3.746 0 0 1 3.296 1.043 3.746 3.746 0 0 1 1.043 3.296A3.745 3.745 0 0 1 21 12Z" />
                                </svg>
                            )}
                        </button>
                    </div>
                ))}
                <label className='border bg-transparent rounded-2xl p-2 items-center text-2xl flex text-gray-600 justify-center cursor-pointer'>
                    <input type="file" multiple className='hidden' onChange={uploadPhoto} />
                    Upload
                    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth="1.5" stroke="currentColor" className="w-6 h-6">
                        <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 0 0 5.25 21h13.5A2.25 2.25 0 0 0 21 18.75V16.5m-13.5-9L12 3m0 0 4.5 4.5M12 3v13.5" />
                    </svg>
                </label>
            </div >
        </>
    );
}