FROM node:latest

RUN curl --proto '=https' --tlsv1.2 https://sh.rustup.rs -sSf | sh -s -- -y
RUN /bin/bash -c 'source "$HOME/.cargo/env"'
RUN git clone https://github.com/iden3/circom.git /app/installation/circom
RUN /root/.cargo/bin/cargo build --release --manifest-path /app/installation/circom/Cargo.toml
RUN /root/.cargo/bin/cargo install --path /app/installation/circom/circom

COPY . .
RUN npm install
RUN npm install -g snarkjs@latest