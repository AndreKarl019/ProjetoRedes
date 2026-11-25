
import argparse
import json
import base64
import logging

import database

from security.key_manager import (
    generate_identity,
    export_identity,
    list_identities
)

from security.peer_auth import public_key_fingerprint

from network.connection_manager import ConnectionManager

from core.debug_logger import debug


logging.basicConfig(level=logging.INFO)


def main():

    parser = argparse.ArgumentParser(
        description="SecurePeer"
    )

    commands = parser.add_subparsers(
        dest="command",
        required=True
    )

    identity = commands.add_parser("identity")

    identity.add_argument(
        "--name",
        required=True
    )

    export = commands.add_parser("export")

    export.add_argument(
        "--name",
        required=True
    )

    receive = commands.add_parser("receive")

    receive.add_argument(
        "--name",
        required=True
    )

    send = commands.add_parser("send")

    send.add_argument(
        "--name",
        required=True
    )

    send.add_argument(
        "--peer",
        required=True
    )

    send.add_argument(
        "--message",
        required=True
    )

    args = parser.parse_args()

    database.initialize_database()

    if args.command == "identity":

        try:

            public = generate_identity(args.name)

            print("\nIdentidade criada!")
            print(json.dumps(public, indent=4))

        except FileExistsError as error:

            print(error)

    elif args.command == "export":

        identity = export_identity(args.name)

        print(json.dumps(
            identity,
            indent=4
        ))

        print(
            "\nFingerprint de criptografia:",
            public_key_fingerprint(
                identity["encryption_public"]
            )
        )

        print(
            "Fingerprint de assinatura:",
            public_key_fingerprint(
                identity["signing_public"]
            )
        )

    elif args.command == "receive":

        manager = ConnectionManager(args.name)

        try:

            manager.start()

            print("SecurePeer receptor iniciado.")
            print("Pressione CTRL+C para encerrar.")

            while True:
                input()

        except KeyboardInterrupt:
            manager.stop()

    elif args.command == "send":

        peer = database.get_peer_by_name(
            args.peer
        )

        if not peer:
            raise ValueError("Peer não cadastrado.")

        manager = ConnectionManager(args.name)

        manager.send(
            peer[0],
            args.message
        )

        print("Mensagem enviada.")


if __name__ == "__main__":

    try:
        main()

    except Exception as error:

        debug.error(str(error))
        raise SystemExit(1)
