import axios from 'axios';

function App() {
  const [dashboardData, setDashboardData] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    axios.get('/api/dashboard')
      .then(response => {
        setDashboardData(response.data);
      })
      .catch(error => {
        console.error("Error fetching dashboard data:", error);
        setError("An error occurred while fetching data.");
      });
  }, []);

  if (error) {
    return <div>Error: {error}</div>;
  }

  if (!dashboardData) {
    return <div>Loading...</div>;
  }

  return (
    <div className="App">
      <h1>Dashboard</h1>
      <div className="metric">
        <h2>Total Revenue</h2>
        <p>${dashboardData.total_revenue.toFixed(2)}</p>
      </div>
      <div className="metric">
        <h2>Number of Invoices</h2>
        <p>{dashboardData.invoice_count}</p>
      </div>
      <div className="metric">
        <h2>Number of Credit Notes</h2>
        <p>{dashboardData.credit_note_count}</p>
      </div>
      <div className="metric">
        <h2>Number of Customers</h2>
        <p>{dashboardData.customer_count}</p>
      </div>
      <a href="/disconnect">Disconnect from QuickBooks</a>
    </div>
  );
}

export default App;import React, { useState, useEffect } from 'react';
import axios from 'axios';

function App() {
  const [dashboardData, setDashboardData] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    axios.get('/api/dashboard')
      .then(response =>

  if (!dashboardData) {
    return <div>Loading...</div>;
  }

  return (
    <div className="App">
      <h1>Dashboard</h1>
      <div className="metr
