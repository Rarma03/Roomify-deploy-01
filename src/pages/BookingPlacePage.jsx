import { useParams } from "react-router-dom";

export default function BookingPlacePage() {
    const { id } = useParams();
    return (
        <div>
            Your Reference Booking id : {id}
        </div>
    );
}