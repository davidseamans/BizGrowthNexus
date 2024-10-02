import React, { useState, useEffect } from 'react';
import axios from 'axios';  // Make sure to include axios

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
  }, []); // The empty array ensures the effect runs only once

  if (error) {
    return <div>Error: {error.message}</div>;
  }

  if (!dashboardData) {
    return <div>Loading...</div>;
  }

  return (
    <div className="App">
      <h1>Dashboard</h1>
      <pre>{JSON.stringify(dashboardData, null, 2)}</pre>
    </div>
  );
}

export default App;
