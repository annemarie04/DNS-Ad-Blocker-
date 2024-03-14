# Use an appropriate base image for your DNS server script
FROM python:3.9-slim-buster

USER root

# Set the working directory in the container
WORKDIR /app

# Copy the DNS server script and requirements file to the container
COPY . ./

# Install the Python dependencies from the requirements file
RUN pip install --no-cache-dir -r requirements.txt

# Expose the DNS server port
EXPOSE 53/udp

# Run the DNS server script
CMD ["python", "dns_add_blocker.py"]