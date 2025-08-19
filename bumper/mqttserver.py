#!/usr/bin/env python3

import logging
import asyncio
import os
import amqtt
from amqtt.broker import Broker
from amqtt.client import MQTTClient
from amqtt.mqtt.constants import QOS_0, QOS_1, QOS_2
from amqtt.errors import BrokerError
import time
import bumper
import json
from datetime import datetime, timedelta
import bumper
from passlib.apps import custom_app_context as pwd_context
from dataclasses import dataclass
from amqtt.plugins.base import BaseAuthPlugin

helperbotlog = logging.getLogger("helperbot")
boterrorlog = logging.getLogger("boterror")
mqttserverlog = logging.getLogger("mqttserver")

class MQTTHelperBot:

    Client = None
    wait_resp_timeout_seconds = 10
    expire_msg_seconds = 10

    def __init__(self, address):
        self.address = address
        self.client_id = "helperbot@bumper/helperbot"
        self.command_responses = []

    async def start_helper_bot(self):

        try:
            if self.Client is None:
                self.Client = MQTTClient(
                    client_id=self.client_id, config={"check_hostname": False, "reconnect_retries": 20}
                )

            username = os.getenv("BUMPER_MQTT_USERNAME")
            password = os.getenv("BUMPER_MQTT_PASSWORD")

            connect_kwargs = {"cafile": bumper.ca_cert}

            if username and password:
                uri = "mqtts://{}:{}@{}:{}/".format(
                    username, password, self.address[0], self.address[1]
                )
            else:
                uri = "mqtts://{}:{}/".format(self.address[0], self.address[1])

            await self.Client.connect(uri, **connect_kwargs)
            await self.Client.subscribe(
                [
                    ("iot/p2p/+/+/+/+/helperbot/bumper/helperbot/+/+/+", QOS_0),
                    ("iot/p2p/+", QOS_0),
                    ("iot/atr/#", QOS_0),
                ]
            )

#        except ConnectionRefusedError as e:
#            helperbotlog.Error(e)
#            pass

#        except asyncio.CancelledError as e:
#            pass

#        except amqtt.client.ConnectException as e:
#            helperbotlog.Error(e)
#            pass

        except Exception as e:
            helperbotlog.exception("{}".format(e))

    async def wait_for_resp(self, requestid):
        try:

            t_end = (
                datetime.now() + timedelta(seconds=self.wait_resp_timeout_seconds)
            ).timestamp()

            while time.time() < t_end:
                await asyncio.sleep(0.1)
                if len(self.command_responses) > 0:
                    for msg in self.command_responses:
                        topic = str(msg["topic"]).split("/")
                        if topic[6] == "helperbot" and topic[10] == requestid:
                            if topic[11] == "j":
                                resppayload = json.loads(msg["payload"])
                            else:
                                resppayload = str(msg["payload"])
                            resp = {"id": requestid, "ret": "ok", "resp": resppayload}
                            self.command_responses.remove(msg)
                            return resp

            return {
                "id": requestid,
                "errno": 500,
                "ret": "fail",
                "debug": "wait for response timed out",
            }
        except asyncio.CancelledError as e:
            helperbotlog.debug("wait_for_resp cancelled by asyncio")
            return {
                "id": requestid,
                "errno": 500,
                "ret": "fail",
                "debug": "wait for response timed out",
            }
        except Exception as e:
            helperbotlog.exception("{}".format(e))
            return {
                "id": requestid,
                "errno": 500,
                "ret": "fail",
                "debug": "wait for response timed out",
            }

    async def send_command(self, cmdjson, requestid):
        if not self.Client._handler.writer is None:
            try:
                ttopic = "iot/p2p/{}/helperbot/bumper/helperbot/{}/{}/{}/q/{}/{}".format(
                    cmdjson["cmdName"],
                    cmdjson["toId"],
                    cmdjson["toType"],
                    cmdjson["toRes"],
                    requestid,
                    cmdjson["payloadType"],
                )
                try:
                    if cmdjson["payloadType"] == "x":
                        await self.Client.publish(
                            ttopic, str(cmdjson["payload"]).encode(), QOS_0
                        )

                    if cmdjson["payloadType"] == "j":
                        await self.Client.publish(
                            ttopic, json.dumps(cmdjson["payload"]).encode(), QOS_0
                        )

                except Exception as e:
                    helperbotlog.exception("{}".format(e))

                resp = await self.wait_for_resp(requestid)

                return resp

            except Exception as e:
                helperbotlog.exception("{}".format(e))
                return {}


class MQTTServer:
    default_config = None
    broker = None

    async def broker_coro(self):

        mqttserverlog.info(
            "Starting MQTT Server at {}:{}".format(self.address[0], self.address[1])
        )        

        try:
            await self.broker.start()

        except BrokerError as e:
            mqttserverlog.exception(e)
            #asyncio.create_task(bumper.shutdown())
            pass

        except Exception as e:
            mqttserverlog.exception("{}".format(e))
            #asyncio.create_task(bumper.shutdown())
            pass

    def __init__(self, address, *, alt_port=None, **kwargs):
        try:
            self.address = address
            self.alt_port = alt_port

            # Default config opts
            passwd_file = os.path.join(
                os.path.join(bumper.data_dir, "passwd")
            )  # For file auth, set user:hash in passwd file see (https://amqtt.readthedocs.io/en/latest/references/amqtt.html#configuration-example)

            allow_anon = False

            for key, value in kwargs.items():
                if key == "password_file":
                    passwd_file = kwargs["password_file"]

                elif key == "allow_anonymous":
                    allow_anon = kwargs["allow_anonymous"]  # Set to True to allow anonymous authentication

            if not os.path.exists(passwd_file):
                allow_anon = True
            else:
                try:
                    with open(passwd_file) as f:
                        has_entry = any(
                            line.strip() and not line.strip().startswith("#") for line in f
                        )
                    if not has_entry:
                        allow_anon = True
                except OSError:
                    allow_anon = True

            # Initialize bot server
            self.default_config = {
                "listeners": {
                    "default": {"type": "tcp"},
                    "tls1": {
                        "bind": "{}:{}".format(address[0], address[1]),
                        "ssl": True,
                        "certfile": bumper.server_cert,
                        "keyfile": bumper.server_key,
                    },
                },
                "plugins": {
                    "amqtt.plugins.sys.broker.BrokerSysPlugin": {
                        "sys_interval": 0
                    },
                    "amqtt.plugins.topic_checking.TopicTabooPlugin": {},
                    "bumper.mqttserver.BumperMQTTServer_Plugin": {
                        "allow_anonymous": allow_anon,
                        "password_file": passwd_file,
                    },
                },
            }

            if self.alt_port and self.alt_port != address[1]:
                self.default_config["listeners"]["tls2"] = {
                    "bind": "{}:{}".format(address[0], self.alt_port),
                    "ssl": True,
                    "certfile": bumper.server_cert,
                    "keyfile": bumper.server_key,
                }

            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

            self.broker = amqtt.broker.Broker(config=self.default_config, loop=loop)

        except Exception as e:
            mqttserverlog.exception("{}".format(e))


class BumperMQTTServer_Plugin(BaseAuthPlugin):
    @dataclass
    class Config:
        allow_anonymous: bool = True
        password_file: str | None = None

    def __init__(self, context):
        super().__init__(context)
        try:
            self._users = dict()
            self._read_password_file()

        except Exception as e:
            mqttserverlog.exception("{}".format(e))

    async def authenticate(self, *, session):
        authenticated = False

        try:
            username = session.username
            password = session.password
            client_id = session.client_id

            if "@" in client_id:
                didsplit = str(client_id).split("@")
                if not (  # if ecouser or bumper aren't in details it is a bot
                    "ecouser" in didsplit[1] or "bumper" in didsplit[1]
                ):
                    tmpbotdetail = str(didsplit[1]).split("/")
                    bumper.bot_add(
                        username,
                        didsplit[0],
                        tmpbotdetail[0],
                        tmpbotdetail[1],
                        "eco-ng",
                    )
                    mqttserverlog.info(f"Bumper Authentication Success - Bot - SN: {username} - DID: {didsplit[0]} - Class: {tmpbotdetail[0]}")                    
                    authenticated = True

                else:
                    tmpclientdetail = str(didsplit[1]).split("/")
                    userid = didsplit[0]
                    realm = tmpclientdetail[0]
                    resource = tmpclientdetail[1]

                    if userid == "helperbot":
                        mqttserverlog.info(f"Bumper Authentication Success - Helperbot: {client_id}")
                        authenticated = True
                    else:
                        auth = False
                        if bumper.check_authcode(didsplit[0], password):
                            auth = True
                        elif bumper.use_auth == False:
                            auth = True

                        if auth:
                            bumper.client_add(userid, realm, resource)
                            mqttserverlog.info(f"Bumper Authentication Success - Client - Username: {username} - ClientID: {client_id}")
                            authenticated = True

                        else:
                            authenticated = False

            # Check for File Auth            
            if username and not authenticated: # If there is a username and it isn't already authenticated
                hash = self._users.get(username, None)
                if hash: # If there is a matching entry in passwd, check hash
                    authenticated = pwd_context.verify(password, hash)
                    if authenticated:
                        mqttserverlog.info(f"File Authentication Success - Username: {username} - ClientID: {client_id}")
                    else:
                        mqttserverlog.info(f"File Authentication Failed - Username: {username} - ClientID: {client_id}")
                else:
                    mqttserverlog.info(f"File Authentication Failed - No Entry for Username: {username} - ClientID: {client_id}")

        except Exception as e:
            mqttserverlog.exception(
                "Session: {} - {}".format(session, e)
            )
            authenticated = False

        # Check for allow anonymous
        allow_anonymous = self.config.allow_anonymous
        if allow_anonymous and not authenticated:  # If anonymous auth is allowed and it isn't already authenticated
            authenticated = True
            self.context.logger.debug(
                f"Anonymous Authentication Success: config allows anonymous - Username: {username}"
            )
            mqttserverlog.info(
                f"Anonymous Authentication Success: config allows anonymous - Username: {username}"
            )

        return authenticated

    def _read_password_file(self):
        password_file = self.config.password_file
        if password_file:
            try:
                with open(password_file) as f:
                    self.context.logger.debug(
                        f"Reading user database from {password_file}"
                    )
                    for l in f:
                        line = l.strip()
                        if not line.startswith('#'):  # Allow comments in files
                            (username, pwd_hash) = line.split(sep=":", maxsplit=3)
                            if username:
                                self._users[username] = pwd_hash
                                self.context.logger.debug(
                                    f"user: {username} - hash: {pwd_hash}"
                                )
                self.context.logger.debug(
                    f"{(len(self._users))} user(s) read from file {password_file}"
                )
            except FileNotFoundError:
                self.context.logger.warning(
                    f"Password file {password_file} not found"
                )

    async def on_broker_client_connected(self, client_id, client_session=None):

        didsplit = str(client_id).split("@")

        bot = bumper.bot_get(didsplit[0])
        if bot:
            bumper.bot_set_mqtt(bot["did"], True)
            return

        clientresource = didsplit[1].split("/")[1]
        client = bumper.client_get(clientresource)
        if client:
            bumper.client_set_mqtt(client["resource"], True)
            return

    async def on_broker_message_received(self, client_id, message):
        self.handle_helperbot_msg(client_id, message)
        
    def handle_helperbot_msg(self, client_id, message):

            if str(message.topic).split("/")[6] == "helperbot":
                # Response to command
                helperbotlog.debug(
                    "Received Response - Topic: {} - Message: {}".format(
                        message.topic, str(message.data.decode("utf-8"))
                    )
                )
                if bumper.mqtt_helperbot:
                    bumper.mqtt_helperbot.command_responses.append(
                        {
                            "time": time.time(),
                            "topic": message.topic,
                            "payload": str(message.data.decode("utf-8")),
                        }
                    )
            elif str(message.topic).split("/")[3] == "helperbot":
                # Helperbot sending command
                helperbotlog.debug(
                    "Send Command - Topic: {} - Message: {}".format(
                        message.topic, str(message.data.decode("utf-8"))
                    )
                )
            elif str(message.topic).split("/")[1] == "atr":
                # Broadcast message received on atr
                if str(message.topic).split("/")[2] == "errors":
                    boterrorlog.error(
                        "Received Error - Topic: {} - Message: {}".format(
                            message.topic, str(message.data.decode("utf-8"))
                        )
                    )
                else:
                    helperbotlog.debug(
                        "Received Broadcast - Topic: {} - Message: {}".format(
                            message.topic, str(message.data.decode("utf-8"))
                        )
                    )

            else:
                helperbotlog.debug(
                    "Received Message - Topic: {} - Message: {}".format(
                        message.topic, str(message.data.decode("utf-8"))
                    )
                )

            # Cleanup "expired messages" > 60 seconds from time
            if bumper.mqtt_helperbot:
                for msg in list(bumper.mqtt_helperbot.command_responses):
                    expire_time = (
                        datetime.fromtimestamp(msg["time"])
                        + timedelta(seconds=bumper.mqtt_helperbot.expire_msg_seconds)
                    ).timestamp()
                    if time.time() > expire_time:
                        helperbotlog.debug(
                            "Pruning Message Due To Expiration - Message Topic: {}".format(
                                msg["topic"]
                            )
                        )
                        bumper.mqtt_helperbot.command_responses.remove(msg)


    async def on_broker_client_disconnected(self, client_id, client_session=None):

        didsplit = str(client_id).split("@")

        bot = bumper.bot_get(didsplit[0])
        if bot:
            bumper.bot_set_mqtt(bot["did"], False)
            return

        clientresource = didsplit[1].split("/")[1]
        client = bumper.client_get(clientresource)
        if client:
            bumper.client_set_mqtt(client["resource"], False)
            return
