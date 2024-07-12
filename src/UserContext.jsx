import axios from "axios";
import { createContext, useEffect, useState } from "react";

export const UserContext = createContext({});

export function UserContextProvider({ children }) {
    const [user, setUser] = useState(null);
    const [ready, setReady] = useState(false);
    useEffect(() => {
        const fetchProfile = async () => {
            try {
                const response = await axios.get('/profile');
                setUser(response.data);
                setReady(true);
            } catch (error) {
                console.error('Error fetching profile:', error);
            }
            finally {
            }
        };

        if (!user) {
            fetchProfile();
        }
    }, [user]); // [] -> they are for dependencies
    return (
        <UserContext.Provider value={{ user, setUser, setReady }}>
            {children}
        </UserContext.Provider>
    );
}

