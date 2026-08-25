FROM python:3.10-slim

# Install system dependencies and curl to install uv
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install uv
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:$PATH"

# Set working directory
WORKDIR /app

# Copy dependency configuration files
COPY pyproject.toml uv.lock* ./

# Install dependencies using uv system-wide
RUN uv pip install --system -r pyproject.toml

# Copy the rest of the project files
COPY . .

# Expose port 10000 for Render
EXPOSE 10000

# Startup script to run FastAPI in the background and Streamlit on port 10000
RUN echo '#!/bin/bash\nuvicorn backend.main:app --host 0.0.0.0 --port 8000 &\nstreamlit run frontend/app.py --server.port=10000 --server.address=0.0.0.0' > /app/start.sh
RUN chmod +x /app/start.sh

CMD ["/app/start.sh"]