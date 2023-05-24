FROM python:3.10
# Run commands from /app directory inside container
WORKDIR /app
# Copy requirements from local to docker image
COPY requirments.txt /app
# Install the dependencies in the docker image
RUN pip install -r requirments.txt --no-cache-dir
# Copy everything from the current dir to the image
COPY . .
CMD ["flask", "run", "--host", "0.0.0.0"]