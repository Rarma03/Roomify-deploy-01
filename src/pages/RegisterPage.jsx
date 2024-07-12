import axios from "axios";
import { useState } from "react"
import { Link } from "react-router-dom"

export default function RegisterPage() {
    let [name, setName] = useState('');
    let [email, setEmail] = useState('');
    let [password, setPassword] = useState('');

    async function registerUser(event) {
        event.preventDefault();
        try {
            await axios.post('/register', {
                name,
                email,
                password
            });
            alert("Registration Complete");

        } catch (e) {
            alert("Registration Failed");
        }
    }

    return (
        <div className="mt-4 grow flex items-center justify-around">
            <div className="mb-32">
                <h1 className="text-4xl text-center mb-4">Register</h1>
                <form className="max-w-md mx-auto" onSubmit={registerUser}>
                    <input type="text"
                        placeholder={"e.g. Raj Verma"}
                        value={name}
                        onChange={event => setName(event.target.value)}
                    />
                    <input type="text"
                        placeholder={"yourmail@email.com"}
                        value={email}
                        onChange={event => setEmail(event.target.value)}
                    />
                    <input type="text"
                        placeholder="password"
                        value={password}
                        onChange={event => setPassword(event.target.value)}

                    />
                    <input type="submit" value="Register" />
                    <div className="text-center">
                        Already a Member?
                        <Link to={'/login'} className="ml-1 text-primary underline ">Login</Link>
                    </div>
                </form>
            </div>
        </div>
    )
}