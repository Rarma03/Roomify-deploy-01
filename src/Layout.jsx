import { Outlet } from "react-router-dom";
import Header from "./Header";
import Footer from "./Footer";

export default function Layout() {
    return (
        <div className="py-6 px-8 flex flex-col min-h-screen">
            <Header></Header>
            <Outlet></Outlet>
            <Footer></Footer>
        </div>
    );
}

