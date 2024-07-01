// BenchmarkMenu.js
import React from 'react';
import './BenchmarkMenu.css';
import { AiOutlineHome } from 'react-icons/ai';

const BenchmarkMenu = ({ setFn, isOpen, toggleMenu }) => {
  const clickMenuItem = (item) => {
    setFn(item);
    toggleMenu(); // Close the menu after clicking a menu item
  };  
  return (
    <div className={`benchmark-menu ${isOpen ? 'open' : 'closed'}`}>
      <div className="menu-icons">
        <div className="menu-icon" onClick={() => clickMenuItem('')}>
          <AiOutlineHome />
        </div>
        <div className="menu-toggle" onClick={toggleMenu}>
          {isOpen ? <>&larr;</> : <>&rarr;</>}
        </div>
      </div>
      {isOpen && (
        <ul>
          <li onClick={() => clickMenuItem('groups')}>Groups</li>
          <li onClick={() => clickMenuItem('sign')}>Signatures</li>
        </ul>
      )}
    </div>
  );
};  
export default BenchmarkMenu;
