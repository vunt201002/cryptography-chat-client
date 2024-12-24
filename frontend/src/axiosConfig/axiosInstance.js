// Import Axios library
import axios from 'axios'

// Create an Axios instance
const axiosInstance = axios.create({
  baseURL: 'http://localhost:9000' // Set the base URL to your backend server
})

// Export the instance for use throughout your application
export default axiosInstance
