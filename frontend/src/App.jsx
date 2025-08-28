import React from 'react'
import LoginPage from './pages/LoginPage'
import { createBrowserRouter, RouterProvider } from 'react-router-dom';
import RegisterPage from './pages/RegisterPage';
import LandingPage from './pages/LandingPage';
import Profile from './pages/Profile';
import Home from './pages/Home';
import { AuthProvider } from './context/AuthContext';

const App = () => {
  const router = createBrowserRouter([
    {
      path: "/",
      children: [
        { index: true, Component: LandingPage },
        { path: "login", Component: LoginPage },
        { path: "register", Component: RegisterPage },
        { path: "home", Component: Home },
        { path: "profile", Component: Profile },
      ],
    },
  ]);

  return (
    <AuthProvider>
      <RouterProvider router={router} />
    </AuthProvider>
  )
}

export default App