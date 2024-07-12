import axios from "axios";
import { useContext, useState } from "react"
import { Link, Navigate } from "react-router-dom"
import { UserContext } from "../UserContext";

export default function LoginPage() {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [redirect, setRedirect] = useState(false);

    const { setUser } = useContext(UserContext);

    async function handleLoginSubmit(event) {
        event.preventDefault();

        try {
            const userInfo = await axios.post('/login', { email, password });
            setUser(userInfo.data);
            alert('Login Success');
            setRedirect(true); // Set redirect state to true after successful login
        } catch (error) {
            alert('Incorrect Login Email or Password');
            console.error('Error logging in:', error);
        }
    }

    // Redirect to '/' route if redirect state is true
    if (redirect) {
        return <Navigate to="/" />;
    }

    return (
        <div className="mt-4 grow flex items-center justify-around">
            <div className="mb-32">
                <h1 className="text-4xl text-center mb-4">Login</h1>
                <form className="max-w-md mx-auto" onSubmit={handleLoginSubmit}>
                    <input type="text"
                        placeholder={"yourmail@email.com"}
                        value={email}
                        onChange={event => setEmail(event.target.value)} />
                    <input type="text" placeholder="password"
                        value={password}
                        onChange={event => setPassword(event.target.value)} />
                    <input type="submit" value="Login"
                    />
                    <div className="text-center">
                        Don't Have a Account?
                        <Link to={'/register'} className="ml-1 text-primary underline ">Register</Link>
                    </div>
                </form>
            </div>
        </div>
    )
}