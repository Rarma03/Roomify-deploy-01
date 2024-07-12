import { Route, Routes } from 'react-router-dom'
import './App.css'
import IndexPage from './pages/IndexPage'
import LoginPage from './pages/LoginPage'
import Layout from './Layout'
import Header from './Header'
import RegisterPage from './pages/RegisterPage'
import axios from 'axios'
import { UserContextProvider } from './UserContext'
import AccountPage from './pages/accountPage'
import PlacesPage from './pages/PlacesPage'
import PlacesFormPage from './pages/PlacesFormPage'
import SinglePlacePage from './pages/SinglePlacePage'
import BookingPage from './pages/BookingPage'
import BookingPlacePage from './pages/BookingPlacePage'


axios.defaults.baseURL = 'http://localhost:4000';
axios.defaults.withCredentials = true;

export default function App() {
  return (
    <UserContextProvider>
      <Routes>
        <Route path='/' element={<Layout></Layout>}>
          <Route index element={<IndexPage />}></Route>
          <Route path='/login' element={<LoginPage />}></Route>
          <Route path='/register' element={<RegisterPage />}></Route>
          <Route path='/account' element={<AccountPage />} />
          <Route path='/account/places' element={<PlacesPage />} />
          <Route path='/account/places/new' element={<PlacesFormPage />} />
          <Route path='/account/places/:id' element={<PlacesFormPage />} />
          <Route path='/place/:id' element={<SinglePlacePage />} />
          <Route path='/account/bookings' element={<BookingPage />} />
          <Route path='/account/bookings/:id' element={<BookingPlacePage />} />
        </Route>
      </Routes >
    </UserContextProvider>
  )
}