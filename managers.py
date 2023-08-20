import json
from typing import Optional
from pathlib import Path
import logging
import pyicloud
import os
import threading
from dataclasses import dataclass, asdict
import time
from base64 import b64decode, b64encode
from getpass import getpass

from rich.logging import RichHandler

import apns
import ids
import imessage


def safe_b64decode(s):
    try:
        return b64decode(s)
    except:
        return None


effects = {
    "InvisibleInk": "com.apple.MobileSMS.expressivesend.invisibleink",
    "Gentle": "com.apple.MobileSMS.expressivesend.gentle",
    "Loud": "com.apple.MobileSMS.expressivesend.loud",
    "Slam": "com.apple.MobileSMS.expressivesend.impact",

    # [Screen Effects]
    "Echo": "com.apple.messages.effect.CKEchoEffect",
    "Spotlight": "com.apple.messages.effect.CKSpotlightEffect",
    "Balloons": "com.apple.messages.effect.CKHappyBirthdayEffect",
    "Confetti": "com.apple.messages.effect.CKConfettiEffect",
    "Heart": "com.apple.messages.effect.CKHeartEffect",
    "Lasers": "com.apple.messages.effect.CKLasersEffect",
    "Fireworks": "com.apple.messages.effect.CKFireworksEffect",
    "Celebration": "com.apple.messages.effect.CKSparklesEffect",
    "ShootingStar": "com.apple.messages.effect.CKShootingStarEffect",
}

class iMessageManager:
    def __init__(self, config: Optional[Path | dict | str] = None,
                 username: Optional[str] = None,
                 password: Optional[str] = None):

        self.config = {}

        if config is not None:
            if isinstance(config, Path) or isinstance(config, str):
                try:
                    with open(config, "r") as f:
                        self.config = json.load(f)
                except FileNotFoundError:
                    logging.warning(f'Couldn\'t find config at "{config}", using username and password login')

            elif isinstance(config, dict):
                self.config = config

        if config is None:
            if username is None or password is None:
                raise ConnectionError("You need either a config file or a username and password to continue")

        self.connection = apns.APNSConnection(
            self.config.get("push", {}).get("key"), self.config.get("push", {}).get("cert")
        )

        self.connection.connect(token=safe_b64decode(self.config.get("push", {}).get("token")))
        self.connection.set_state(1)
        self.connection.filter(["com.apple.madrid"])

        logging.info("Connected to apple... moving on to user login...")

        self.user = ids.IDSUser(self.connection)

        if self.config.get("auth", {}).get("cert") is not None:
            auth_keypair = ids._helpers.KeyPair(self.config["auth"]["key"], self.config["auth"]["cert"])
            user_id = self.config["auth"]["user_id"]
            handles = self.config["auth"]["handles"]
            self.user.restore_authentication(auth_keypair, user_id, handles)
        else:
            username = username
            password = password

            self.user.authenticate(username, password)

        self.user.encryption_identity = ids.identity.IDSIdentity(
            encryption_key=self.config.get("encryption", {}).get("rsa_key"),
            signing_key=self.config.get("encryption", {}).get("ec_key"),
        )

        if (
                self.config.get("id", {}).get("cert") is not None
                and self.user.encryption_identity is not None
        ):
            id_keypair = ids._helpers.KeyPair(self.config["id"]["key"], self.config["id"]["cert"])
            self.user.restore_identity(id_keypair)
        else:
            logging.info("Registering new identity...")
            import emulated.nac

            vd = emulated.nac.generate_validation_data()
            vd = b64encode(vd).decode()

            self.user.register(vd)

        self.imessage = imessage.iMessageUser(self.connection, self.user)
        self.current_participants = []

    def write_current_config(self, path: Optional[Path | str] = "./config.json"):
        self.config["encryption"] = {
            "rsa_key": self.user.encryption_identity.encryption_key,
            "ec_key": self.user.encryption_identity.signing_key,
        }
        self.config["id"] = {
            "key": self.user._id_keypair.key,
            "cert": self.user._id_keypair.cert,
        }
        self.config["auth"] = {
            "key": self.user._auth_keypair.key,
            "cert": self.user._auth_keypair.cert,
            "user_id": self.user.user_id,
            "handles": self.user.handles,
        }
        self.config["push"] = {
            "token": b64encode(self.user.push_connection.token).decode(),
            "key": self.user.push_connection.private_key,
            "cert": self.user.push_connection.cert,
        }

        with open(path, "w") as f:
            json.dump(self.config, f, indent=4)

    def receive(self):
        msg = self.imessage.receive()
        if msg is not None:
            logging.info(msg.to_string())
        return msg

    def send(self, text: str, participants: Optional[list] = None, effect: Optional[str] = None):
        if participants is None:
            participants = self.current_participants

        self.imessage.send(imessage.iMessage(
            text=text,
            participants=participants,
            sender=self.user.current_handle,
            effect=effect
        ))

    def print_handles(self):
        for h in self.user.handles:
            if h == self.user.current_handle:
                print(f'\t{h} (current)')
            else:
                print(f'\t{h}')

    def set_current_handle(self, handle: str):
        h = self.fixup_handle(handle)
        if h in self.user.handles:
            logging.info(f'Using {h} as handle')
            self.user.current_handle = h
        else:
            logging.error(f'Handle {h} not found')

    def set_current_participants(self, particpants: list):
        particpants = [self.fixup_handle(h) for h in particpants]
        self.current_participants = particpants

    @staticmethod
    def fixup_handle(handle):
        if handle.startswith('tel:+'):
            return handle
        elif handle.startswith('mailto:'):
            return handle
        elif handle.startswith('tel:'):
            return 'tel:+' + handle[4:]
        elif handle.startswith('+'):
            return 'tel:' + handle
        # If the handle starts with a number
        elif handle[0].isdigit():
            # If the handle is 10 digits, assume it's a US number
            if len(handle) == 10:
                return 'tel:+1' + handle
            # If the handle is 11 digits, assume it's a US number with country code
            elif len(handle) == 11:
                return 'tel:+' + handle
        else:  # Assume it's an email
            return 'mailto:' + handle


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.NOTSET, format="%(message)s", datefmt="[%X]", handlers=[RichHandler()]
    )

    # Set sane log levels
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("py.warnings").setLevel(logging.ERROR)  # Ignore warnings from urllib3
    logging.getLogger("asyncio").setLevel(logging.WARNING)
    logging.getLogger("jelly").setLevel(logging.INFO)
    logging.getLogger("nac").setLevel(logging.INFO)
    logging.getLogger("apns").setLevel(logging.INFO)
    logging.getLogger("albert").setLevel(logging.INFO)
    logging.getLogger("ids").setLevel(logging.DEBUG)
    logging.getLogger("bags").setLevel(logging.INFO)
    logging.getLogger("imessage").setLevel(logging.DEBUG)

    logging.captureWarnings(True)

    INPUT_QUEUE = apns.IncomingQueue()


    def input_thread():
        from prompt_toolkit import prompt
        while True:

            try:
                msg = prompt('>> ')
            except:
                msg = 'quit'
            INPUT_QUEUE.append(msg)

    current_participants = []
    current_effect = None

    if os.path.exists("./config.json"):
        iManager = iMessageManager(config="./config.json")
    else:
        iManager = iMessageManager(username=input("Username: "), password=input("Password: "))
        iManager.write_current_config()
    threading.Thread(target=input_thread, daemon=True).start()
    while True:
        msg = iManager.receive()
        if msg is not None:
            # print(f'[{msg.sender}] {msg.text}')
            print(msg.to_string())

            attachments = msg.attachments()
            if len(attachments) > 0:
                attachments_path = f"attachments/{msg.id}/"
                os.makedirs(attachments_path, exist_ok=True)

                for attachment in attachments:
                    with open(attachments_path + attachment.name, "wb") as attachment_file:
                        attachment_file.write(attachment.versions[0].data())

                print(
                    f"({len(attachments)} attachment{'s have' if len(attachments) != 1 else ' has'} been downloaded and put "
                    f"in {attachments_path})")

        if len(INPUT_QUEUE) > 0:
            msg = INPUT_QUEUE.pop()
            if msg == '': continue
            if msg == 'help' or msg == 'h':
                print('help (h): show this message')
                print('quit (q): quit')
                # print('send (s) [recipient] [message]: send a message')
                print('filter (f) [recipient]: set the current chat')
                print('effect (e): adds an iMessage effect to the next sent message')
                print('note: recipient must start with tel: or mailto: and include the country code')
                print('handle <handle>: set the current handle (for sending messages)')
                print('\\: escape commands (will be removed from message)')
            elif msg == 'quit' or msg == 'q':
                break
            elif msg == 'effect' or msg == 'e' or msg.startswith("effect ") or msg.startswith("e "):
                msg = msg.split(" ")
                if len(msg) < 2 or msg[1] == "":
                    print("effect [effect namespace]")
                    print("---- EFFECTS ----")
                    print("\n".join(effects.keys()))
                else:
                    print(f"next message will be sent with [{msg[1]}]")
                    effect = effects.get(msg[1])
                    current_effect = effect

            elif msg == 'filter' or msg == 'f' or msg.startswith('filter ') or msg.startswith('f '):
                # Set the curernt chat
                msg = msg.split(' ')
                if len(msg) < 2 or msg[1] == '':
                    print('filter [recipients]')
                else:
                    iManager.set_current_participants(msg[1:])
                    print(f'Filtering to {iManager.current_participants}')

            elif msg == 'handle' or msg.startswith('handle '):
                msg = msg.split(' ')
                if len(msg) < 2 or msg[1] == '':
                    print('handle [handle]')
                    print('Available handles:')
                    iManager.print_handles()

                else:
                    iManager.set_current_handle(msg[1])

            elif iManager.current_participants:
                if msg.startswith('\\'):
                    msg = msg[1:]
                iManager.send(
                    text=msg,
                    effect=current_effect
                )
                current_effect = None
            else:
                print('No chat selected, use help for help')

        time.sleep(0.1)
