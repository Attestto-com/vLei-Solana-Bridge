FROM backpackapp/build:v0.31.0

# ── Solana CLI (Agave 2.1.14) ────────────────────────────────────────
RUN sh -c "$(curl -sSfL https://release.anza.xyz/v2.1.14/install)"
ENV PATH="/root/.local/share/solana/install/active_release/bin:${PATH}"

# ── Anchor CLI 0.32.1 ────────────────────────────────────────────────
RUN cargo install --git https://github.com/coral-xyz/anchor --tag v0.32.1 anchor-cli --locked --force

# ── Node 20 + pnpm (for TS tests) ────────────────────────────────────
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && npm i -g pnpm@9

# ── Rust toolchain pinned to match rust-toolchain file ────────────────
RUN rustup install 1.75.0 && rustup default 1.75.0

# ── Generate a throwaway keypair for localnet testing ─────────────────
RUN solana-keygen new --no-bip39-passphrase -o /root/.config/solana/id.json \
    && solana config set --url localhost

WORKDIR /workdir

# ── Copy manifests first (layer cache for deps) ──────────────────────
COPY Cargo.toml Cargo.lock rust-toolchain ./
COPY programs/attestto-vlei-sbt/Cargo.toml programs/attestto-vlei-sbt/Cargo.toml
COPY package.json pnpm-lock.yaml* ./
COPY Anchor.toml ./

# ── Install JS deps ──────────────────────────────────────────────────
RUN pnpm install --frozen-lockfile || pnpm install

# ── Copy the rest of the source ──────────────────────────────────────
COPY . .

# ── Build the Anchor program (--no-idl: anchor-syn 0.32.1 IDL build
#    has a proc_macro2::Span::local_file bug) ─────────────────────────
RUN anchor build --no-idl
