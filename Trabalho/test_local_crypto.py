
import base64
import uuid

from security.key_manager import (
    generate_identity,
    export_identity,
    delete_identity
)

from security.message_crypto import (
    derive_shared_key,
    encrypt_message,
    decrypt_message
)

from security.peer_auth import (
    sign_packet,
    verify_packet,
    canonical_json
)


def run_test():

    suffix = uuid.uuid4().hex[:8]

    name_a = "teste_a_" + suffix
    name_b = "teste_b_" + suffix

    try:

        print("\n[1] Criando identidades...")

        generate_identity(name_a)
        generate_identity(name_b)

        identity_a = export_identity(name_a)
        identity_b = export_identity(name_b)

        print("[OK] Duas identidades criadas.")

        print("\n[2] Derivando chaves compartilhadas...")

        key_a = derive_shared_key(
            name_a,
            identity_b["encryption_public"]
        )

        key_b = derive_shared_key(
            name_b,
            identity_a["encryption_public"]
        )

        assert key_a == key_b

        print("[OK] As duas máquinas derivaram a mesma chave.")

        print("\n[3] Criptografando mensagem...")

        message = "Teste de criptografia SecurePeer!"

        header = {
            "version": 1,
            "type": "message",
            "message_id": str(uuid.uuid4()),
            "sender": name_a,
            "recipient": name_b,
            "timestamp": 1790000000
        }

        aad = canonical_json(header)

        encrypted = encrypt_message(
            message,
            key_a,
            aad
        )

        packet = {
            **header,
            "payload": encrypted
        }

        print("[OK] Mensagem criptografada.")

        print("\n[4] Assinando pacote...")

        packet = sign_packet(
            name_a,
            packet
        )

        print("[OK] Assinatura criada.")

        print("\n[5] Verificando assinatura...")

        valid = verify_packet(
            packet,
            identity_a["signing_public"]
        )

        assert valid

        print("[OK] Assinatura válida.")

        print("\n[6] Descriptografando mensagem...")

        decrypted = decrypt_message(
            packet["payload"],
            key_b,
            aad
        )

        assert decrypted == message

        print("[OK] Mensagem recuperada:")
        print(decrypted)

        print("\n[7] Testando detecção de alteração...")

        altered = dict(packet)
        altered["recipient"] = "outro_destino"

        valid = verify_packet(
            altered,
            identity_a["signing_public"]
        )

        assert not valid

        print("[OK] Alteração detectada.")

        print("\nTODOS OS TESTES PASSARAM!")

    finally:

        delete_identity(name_a)
        delete_identity(name_b)


if __name__ == "__main__":
    run_test()
