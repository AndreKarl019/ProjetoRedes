
from pathlib import Path

# Diretório principal
BASE_DIR = Path(__file__).resolve().parent.parent

# Armazenamento
DATA_DIR = BASE_DIR / "data"
IDENTITIES_DIR = DATA_DIR / "identities"
DATABASE_PATH = DATA_DIR / "securepeer.db"

# WireGuard
WIREGUARD_INTERFACE = "SecurePeer"
WIREGUARD_PORT = 51820

# Rede virtual
DEFAULT_TUNNEL_NETWORK = "10.77.0.0/24"

# Comunicação
MESSAGE_HOST = "0.0.0.0"
MESSAGE_PORT = 8765

# Limites
MAX_MESSAGE_SIZE = 1024 * 1024
MAX_CONNECTIONS = 10
SOCKET_TIMEOUT = 10

# Criptografia
ENCRYPTION_ALGORITHM = "AES-256-GCM"
KEY_EXCHANGE_ALGORITHM = "X25519"
SIGNATURE_ALGORITHM = "Ed25519"

# DEBUG
DEBUG_MODE = True

# Criar diretórios necessários
DATA_DIR.mkdir(parents=True, exist_ok=True)
IDENTITIES_DIR.mkdir(parents=True, exist_ok=True)
