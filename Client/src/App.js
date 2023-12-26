import React, { useState } from 'react';
import './App.scss'; // Make sure the path is correct
import logo from './logo.png';


const YourComponent = () => {
  const [showSignup, setShowSignup] = useState(false);

  const handleSignupClick = () => {
    setShowSignup(true);
  };

  const handleSigninClick = () => {
    setShowSignup(false);
  };

  return (
    <div className="container">
      <div className="welcome">
        <div className={`pinkbox ${showSignup ? 'signup' : 'signin'}`}>
          <div className={`signup nodisplay ${showSignup ? 'show' : ''}`}>
            <h1>register</h1>
            <form autoComplete="off">
              <input type="text" placeholder="username" />
              <input type="email" placeholder="email" />
              <input type="password" placeholder="password" />
              <input type="password" placeholder="confirm password" />
              <button className="button submit">create account </button>
            </form>
          </div>
          <div className={`signin ${showSignup ? 'nodisplay' : 'show'}`}>
            <h1>sign in</h1>
            <form className="more-padding" autoComplete="off">
              <input type="text" placeholder="username" />
              <input type="password" placeholder="password" />
              <div className="checkbox">
                <input type="checkbox" id="remember" /><label htmlFor="remember">remember me</label>
              </div>
              <button className="button submit">login</button>
            </form>
          </div>
        </div>
        <div className="leftbox">
          <h2 className="title"><span>THRIFTY</span><br />TRACKER</h2>
          <p className="desc">Track, Save, Thrive: <span>Your Financial Companion</span></p>
          <img className="flower " src={logo} alt="Thrifty Tracker" />

          <p className="account">have an account?</p>
          <button className="button" onClick={handleSigninClick}>login</button>
        </div>
        <div className="rightbox">
          <h2 className="title"><span>THRIFTY</span>&<br />TRACKER</h2>
          <p className="desc"> Track, Save, Thrive: <span>Your Financial Companion</span></p>
          <img className="flower" src={logo} />
          <p className="account">don't have an account?</p>
          <button className="button" onClick={handleSignupClick}>sign up</button>
        </div>
      </div>
    </div>
  );
};

export default YourComponent;
