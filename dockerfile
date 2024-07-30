FROM python:3.9-slim

# Set the working directory in the container to `/app`
WORKDIR /app

# Copy the requirements file
COPY requirements.txt .

# Install the dependencies
RUN pip install -r requirements.txt

# Copy the main.py file
COPY main.py .

# Make sure the permissions are correct
USER root

EXPOSE 8501

# Run the command to run the app
CMD ["streamlit", "run", "main.py"]

