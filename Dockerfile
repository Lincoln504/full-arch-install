# Use a Node.js base image
FROM node:16-alpine

# Set the working directory in the container
WORKDIR /app

# Copy package.json and package-lock.json (if it exists)
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy the rest of the application code
COPY . .

# Build the application
RUN npm run build

# Expose the port your application runs on
EXPOSE 3000 # Replace with your application's port

# Start the application
CMD ["npm", "start"]
