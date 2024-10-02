import React, { useState, useEffect } from 'react';
import axios from 'axios'; // Make sure to import axios here

function App() {
  const [dashboardData, setDashboardData] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    axios.get('/api/dashboard')
      .then(response => {
        setDashboardData(response.data);
      })
      .catch(error => {
        setError(error);
      });
  }, []); // Empty dependency array to run effect only once on mount

  if (error) {
    return <div>Error: {error.message}</div>;
  }

  if (!dashboardData) {
    return <div>Loading...</div>;
  }
  return (
    <div>
      {/* Render dashboard data here */}
      <h1>Dashboard Data</h1>
      <pre>{JSON.stringify(dashboardData, null, 2)}</pre>
    </div>
  );
}

export default App;
