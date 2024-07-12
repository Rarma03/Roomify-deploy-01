import { useContext, useEffect } from "react";
import { UserContext } from "../UserContext";
import { Link, Navigate, useParams, useNavigate } from "react-router-dom";
import axios from "axios";
import PlacesPage from "./PlacesPage";
import AccountNav from "../AccountNav";

export default function AccountPage() {
    const { user, setUser, ready, setReady } = useContext(UserContext);
    const navigate = useNavigate();

    useEffect(() => {
        const fetchUserData = async () => {
            try {
                const response = await axios.get('/profile');
                setUser(response.data);
                setReady(true);
                localStorage.setItem('user', JSON.stringify(response.data));
            } catch (error) {
                console.error('Error fetching user data:', error);
                setReady(false);
                localStorage.removeItem('user');
                navigate('/login');
            }
        };

        fetchUserData();
    }, [setUser, setReady, navigate]);

    let { subpage } = useParams();
    if (subpage === undefined) {
        subpage = 'profile';
    }

    async function logout() {
        try {
            await axios.post('/logout');
            setUser(null);
            localStorage.removeItem('user');
            navigate('/login');
        } catch (error) {
            console.error('Error logging out:', error);
        }
    }



    if (ready == false) {
        return 'Loading...';
    }

    if (!user) {
        return <Navigate to='/login' />;
    }

    return (
        <div>
            <AccountNav />

            {subpage === 'profile' && (
                <div className="text-center max-w-lg mx-auto mt-20">
                    Logged in as {user.name} {user.email}
                    <input
                        type="submit"
                        value="Logout"
                        className="mt-2 max-w-sm bg-primary"
                        onClick={logout}
                    />
                </div>
            )}
            {subpage === 'places' && (
                <PlacesPage />
            )}
        </div>
    );
}
