export default function Footer() {
    return (
        <div className="border-t -mx-8 py-8 px-4 bg-gray-100 mt-10">
            <div className="grid grid-cols-1 md:grid-cols-3">
                <div>
                    <h2 className="font-semibold text-1xl mt-5">Support</h2>
                    <ul>
                        <li>Help center</li>
                        <li>AirCover</li>
                        <li>Anti-discrimination</li>
                        <li>Cancellation Options</li>
                        <li>Report neighbourhood concern</li>
                    </ul>
                </div>
                <div className="border-t mt-4 md:border-l md:border-t-0 md:px-4 md:mt-0">
                    <h2 className="font-semibold text-1xl mt-5 ">Hosting</h2>
                    <ul>
                        <li>Roomify your home</li>
                        <li>AirCover for Hosts</li>
                        <li>Hosting resources</li>
                        <li>Community forum</li>
                        <li>Hosting responsibly</li>
                        <li>Join a free Hosting class</li>
                    </ul>
                </div>
                <div className="border-t mt-4 md:border-l md:border-t-0 md:px-4 md:mt-0">
                    <h2 className="font-semibold text-1xl mt-5">Roomify</h2>
                    <ul>
                        <li>NewsRoom</li>
                        <li>New Features</li>
                        <li>Careers</li>
                        <li>Investors</li>
                        <li>Customer Support</li>
                    </ul>
                </div>
            </div>
        </div>
    );
}