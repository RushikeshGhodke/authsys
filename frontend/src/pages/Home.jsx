import React, { useState } from 'react';
import Navbar from '../components/Navbar';

const Home = () => {
    return (
        <>
            <Navbar />
            <div className="pt-16">
                {/* Content goes here */}
                <div className="min-h-96 bg-[#F9F9F9] p-8">
                    <div className="max-w-7xl mx-auto">
                        <h1 className="text-3xl font-bold text-[#0061A1] mb-6 poppins-bold">Welcome to Home Page</h1>
                        <p className="text-[#7D7D7D] poppins-regular">This is the home page content.</p>
                    </div>
                </div>
            </div>
        </>
    );
};

export default Home;