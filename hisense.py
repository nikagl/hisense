import re
import uuid
import hashlib
import time
import json
import logging
import paho.mqtt.client as mqtt
from pprint import pprint
import keyboard 
import argparse
import os
import sys
import random

script_directory = os.path.dirname(os.path.abspath(sys.argv[0]))

# Configuration
tv_ip = "192.168.178.134"
random_mac = True # Set to False if you want to use a specific MAC address
certfile = os.path.join(script_directory, "./rcm_certchain_pem.cer")
keyfile = os.path.join(script_directory, "./rcm_pem_privkey.pkcs8")
credentialsfile = os.path.join(script_directory, "credentials.json") 
check_interval = 0.1
debug = True

# Logging setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class TVAuthenticator:
    def __init__(self):
        self.reply = None
        self.authentication_payload = None
        self.authentication_code_payload = None
        self.tokenissuance = None
        self.accesstoken = None
        self.accesstoken_time = None
        self.accesstoken_duration_day = None
        self.refreshtoken = None
        self.refreshtoken_time = None
        self.refreshtoken_duration_day = None
        self.client_id = None
        self.username = None
        self.password = None
        self.timestamp = None
        self.authenticated = False

        self.topicTVUIBasepath = None
        self.topicTVPSBasepath = None
        self.topicMobiBasepath = None
        self.topicBrcsBasepath = None
        self.topicRemoBasepath = None

        self.info = None

    @staticmethod
    # Sum all digits of a number
    def cross_sum(n):
        return sum(int(digit) for digit in str(n))

    @staticmethod
    # Convert a string to a hash
    def string_to_hash(input_str):
        return hashlib.md5(input_str.encode("utf-8")).hexdigest().upper()

    # Action when connected
    def on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            client.connected_flag = True
            if debug:
                logging.info("Connected to MQTT broker")
        else:
            logging.error(f"Bad connection. Returned code: {rc}")
            client.cancel_loop = True

    # Action when message received
    def on_message(self, client, userdata, msg):
        if debug:
            logging.info(f"Message received: {msg.payload.decode('utf-8')} on topic {msg.topic}")
        self.authenticated = False
        self.reply = msg

    # Action when subscribed
    def on_subscribe(self, client, userdata, mid, granted_qos):
        if debug:
            logging.info(f"Subscribed: {mid} {granted_qos}")

    # Action when published
    def on_publish(self, client, userdata, mid):
        if debug:
            logging.info(f"Published message {mid}")

    # Action when disconnected
    def on_disconnect(self, client, userdata, rc):
        if debug:
            logging.info(f"Disconnected. Reason: {rc}")
        client.cancel_loop = True

    # Action when authentication message received
    def on_authentication(self, mosq, obj, msg):
        if debug:
            logging.info(f"Authentication message received: {msg.payload.decode('utf-8')} on topic {msg.topic}")
        self.authentication_payload = msg

    # Action when authentication code message received
    def on_authentication_code(self, mosq, obj, msg):
        if debug:
            logging.info(f"Authentication code message received: {msg.payload.decode('utf-8')} on topic {msg.topic}")
        self.authentication_code_payload = msg

    # Action when token issuance message received
    def on_tokenissuance(self, mosq, obj, msg):
        if debug:
            logging.info(f"Token issuance message received: {msg.payload.decode('utf-8')} on topic {msg.topic}")
        self.tokenissuance = msg

    # Action when information message received
    def on_info(self, mosq, obj, msg):
        if debug:
            logging.info(f"Information message received: {msg.payload.decode('utf-8')} on topic {msg.topic}")
        self.info = msg.payload.decode('utf-8')

    # Wait for a message (condition is a lambda function that returns True or False)
    def wait_for_message(self, condition, check_interval=1, debug=False):
        initial_start_time = time.time()
        feedback_delay = initial_start_time
        timeout = 60  # Maximum wait time in seconds
        print("Waiting for message... (press and hold escape to cancel waiting)")
        time.sleep(1)  # Initial delay to prevent false negatives

        print("Waiting...", end='', flush=True)
        while condition():
            # check for keyboard press
            if keyboard.is_pressed('esc'):
                print("\nEscape pressed. Exiting...")
                break

            # only add a dot every 3 seconds
            current_time = time.time()
            if current_time - feedback_delay >= 3:
                print(".", end='', flush=True)
                feedback_delay = current_time

            # check if timeout is reached
            if current_time - initial_start_time >= timeout:
                print("\nTimeout reached. Exiting...")
                break

            # wait a bit before checking again
            time.sleep(check_interval)
        
        print("")
    
    # Open the client and connect to the TV
    def create_mqtt_client(self, client_id, certfile, keyfile, username, password, userdata=None):
        if debug:
            logging.info("Creating MQTT client...")
        client = mqtt.Client(client_id=client_id, clean_session=True, userdata=userdata, protocol=mqtt.MQTTv311, transport="tcp")
        client.tls_set(ca_certs=None, certfile=certfile, keyfile=keyfile, cert_reqs=mqtt.ssl.CERT_NONE, tls_version=mqtt.ssl.PROTOCOL_TLS)
        client.tls_insecure_set(True)
        client.username_pw_set(username=username, password=password)

        # Attach event handlers
        client.on_connect = self.on_connect
        client.on_message = self.on_message
        client.on_publish = self.on_publish
        client.on_disconnect = self.on_disconnect
        client.enable_logger()

        client.connected_flag = False
        client.cancel_loop = False

        return client

    # Refresh the token
    def refresh_token(self):
        if debug:
            logging.info("Refreshing token...")

        client = self.create_mqtt_client(client_id=self.client_id, certfile=certfile, keyfile=keyfile, username=self.username, password=self.refreshtoken)
        if debug:
            logging.info(f"Adding callback message to {self.topicMobiBasepath}platform_service/data/tokenissuance")
        client.message_callback_add(self.topicMobiBasepath + 'platform_service/data/tokenissuance', self.on_tokenissuance)

        client.connect_async(tv_ip, 36669, 60)
        client.loop_start()

        self.wait_for_message(lambda: not client.connected_flag and not client.cancel_loop)
        if client.cancel_loop:
            logging.error("Failed to connect to MQTT broker. Exiting...")
            client.loop_stop()
            client.disconnect()
            return

        client.subscribe(self.topicMobiBasepath + 'platform_service/data/tokenissuance')
        client.publish(f"/remoteapp/tv/platform_service/{self.client_id}/data/gettoken", json.dumps({"refreshtoken": self.refreshtoken}))

        self.wait_for_message(lambda: self.tokenissuance is None or client.cancel_loop)
        if client.cancel_loop:
            logging.error("Failed to connect to MQTT broker. Exiting...")
            client.loop_stop()
            client.disconnect()
            return

        credentials = json.loads(self.tokenissuance.payload.decode())
        credentials.update({"client_id": self.client_id, "username": self.username, "password": self.password})
        pprint(credentials)

        if debug:
            logging.info('Token issued successfully')
        with open(credentialsfile, 'w') as file:
            json.dump(credentials, file, indent=4)
        if debug:
            logging.info('Credentials saved to {credentialsfile}')        

        client.loop_stop()
        client.disconnect()

        self.accesstoken = credentials["accesstoken"]
        self.accesstoken_time = credentials["accesstoken_time"]
        self.accesstoken_duration_day = credentials["accesstoken_duration_day"]
        self.refreshtoken = credentials["refreshtoken"]
        self.refreshtoken_time = credentials["refreshtoken_time"]
        self.refreshtoken_duration_day = credentials["refreshtoken_duration_day"]
        self.client_id = credentials['client_id']
        self.username = credentials['username']
        self.password = credentials['password']
        self.authenticated = True

        return credentials["accesstoken"]

    def random_mac_address(self):
        # A MAC address has 6 pairs of hexadecimal digits
        mac = [random.randint(0x00, 0xFF) for _ in range(6)]
        return ':'.join(f'{octet:02x}' for octet in mac)

    # Check and refresh the token if needed
    def check_and_refresh_token(self):
        current_time = time.time()
        if debug:
            logging.info(f"Current time is {time.ctime(current_time)}")

        expiration_time = int(self.accesstoken_time) + (int(self.accesstoken_duration_day) * 24 * 60 * 60)
        if debug:
            logging.info(f"Access Token expires at {time.ctime(expiration_time)}")

        refresh_expiration_time = int(self.refreshtoken_time) + (int(self.refreshtoken_duration_day) * 24 * 60 * 60)
        if debug:
            logging.info(f"Refresh Token expires at {time.ctime(refresh_expiration_time)}")

        if current_time <= expiration_time:
            if debug:
                logging.info("Token still valid, no need to refresh")
            time_diff = expiration_time - current_time
            days = time_diff // (24 * 60 * 60)
            hours = (time_diff % (24 * 60 * 60)) // (60 * 60)
            minutes = (time_diff % (60 * 60)) // 60
            seconds = time_diff % 60
            if debug:
                logging.info(f"Token expires in {int(days)} days, {int(hours)} hours, {int(minutes)} minutes, and {int(seconds)} seconds")
            return self.accesstoken

        if debug:
            logging.info("Token not valid, refreshing the token")

        return self.refresh_token()
    
    # Define the hashes, username, password and client_id
    def define_hashes(self):
        self.timestamp = int(time.time())

        if random_mac:
            # generate a random mac-address
            mac = self.random_mac_address()
        else:
            mac = ':'.join(re.findall('..', '%012x' % uuid.getnode())).upper()

        if debug:
            logging.info(f'MAC Address: {mac}')

        first_hash = self.string_to_hash("&vidaa#^app")
        second_hash = self.string_to_hash(f"38D65DC30F45109A369A86FCE866A85B${mac}")
        last_digit_of_cross_sum = self.cross_sum(self.timestamp) % 10
        third_hash = self.string_to_hash(f"his{last_digit_of_cross_sum}h*i&s%e!r^v0i1c9")
        fourth_hash = self.string_to_hash(f"{self.timestamp}${third_hash[:6]}")

        self.username = f"his${self.timestamp}"
        self.password = fourth_hash

        if debug:
            logging.info(f'First Hash: {first_hash}')
            logging.info(f'Second Hash: {second_hash}')
            logging.info(f'Third Hash: {third_hash}')
            logging.info(f'Fourth Hash: {fourth_hash}')

        self.client_id = f"{mac}$his${second_hash[:6]}_vidaacommon_001"
        if debug:
            logging.info(f'Client ID: {self.client_id}')

    # Define the topic paths
    def define_topic_paths(self):
        self.topicTVUIBasepath = f"/remoteapp/tv/ui_service/{self.client_id}/"
        self.topicTVPSBasepath = f"/remoteapp/tv/platform_service/{self.client_id}/"
        self.topicMobiBasepath = f"/remoteapp/mobile/{self.client_id}/"
        self.topicBrcsBasepath = f"/remoteapp/mobile/broadcast/"
        self.topicRemoBasepath = f"/remoteapp/tv/remote_service/{self.client_id}/"

    # Authenticate with the TV and write the credentials to the credentials file
    def generate_creds(self):
        self.define_hashes()
        self.define_topic_paths()

        client = self.create_mqtt_client(client_id=self.client_id, certfile=certfile, keyfile=keyfile, username=self.username, password=self.password)
        if debug:
            logging.info(f"Adding callback messages for authentication...")
        client.message_callback_add(self.topicMobiBasepath + 'ui_service/data/authentication', self.on_authentication)
        client.message_callback_add(self.topicMobiBasepath + 'ui_service/data/authenticationcode', self.on_authentication_code)
        client.message_callback_add(self.topicBrcsBasepath + 'ui_service/data/hotelmodechange', self.on_message)
        client.message_callback_add(self.topicMobiBasepath + 'platform_service/data/tokenissuance', self.on_tokenissuance)

        client.connect_async(tv_ip, 36669, 60)
        client.loop_start()

        self.wait_for_message(lambda: not client.connected_flag and not client.cancel_loop)
        if client.cancel_loop:
            logging.error("Failed to connect to MQTT broker. Exiting...")
            client.loop_stop()
            client.disconnect()
            return

        client.subscribe([
            (self.topicBrcsBasepath + 'ui_service/state', 0),
            (self.topicTVUIBasepath + 'actions/vidaa_app_connect', 0),
            (self.topicMobiBasepath + 'ui_service/data/authentication', 0),
            (self.topicMobiBasepath + 'ui_service/data/authenticationcode', 0),
            (self.topicBrcsBasepath + "ui_service/data/hotelmodechange", 0),
            (self.topicMobiBasepath + 'platform_service/data/tokenissuance', 0),
        ])

        if debug:
            logging.info('Publishing message to actions/vidaa_app_connect...')
        client.publish(self.topicTVUIBasepath + "actions/vidaa_app_connect", '{"app_version":2,"connect_result":0,"device_type":"Mobile App"}')

        self.wait_for_message(lambda: self.authentication_payload is None or client.cancel_loop)
        if client.cancel_loop:
            logging.error("Failed to connect to MQTT broker. Exiting...")
            client.loop_stop()
            client.disconnect()
            return

        if self.authentication_payload.payload.decode() != '""':
            logging.error('Problems with the authentication message!')
            logging.error(self.authentication_payload.payload)
            return

        if debug:
            logging.info(f'Subscribing to {self.topicMobiBasepath}ui_service/data/authenticationcode...')
        client.subscribe(self.topicMobiBasepath + 'ui_service/data/authenticationcode')

        authsuccess = False
        while not authsuccess:
            auth_num = input("Enter the four digits displayed on your TV: ")
            client.publish(self.topicTVUIBasepath + "actions/authenticationcode", f'{{"authNum":{auth_num}}}')

            self.wait_for_message(lambda: self.authentication_code_payload is None or client.cancel_loop)
            if client.cancel_loop:
                logging.error("Failed to connect to MQTT broker. Exiting...")
                client.loop_stop()
                client.disconnect()
                return

            payload = json.loads(self.authentication_code_payload.payload.decode())
            if not 'result' in payload or payload['result'] != 1:
            # if json.loads(self.authentication_code_payload.payload.decode()) != {"result": 1, "info": ""}:
                if debug:
                    logging.error('Problems with the authentication message!')
                    logging.error(self.authentication_code_payload.payload)
            else:
                authsuccess = True

        if debug:
            logging.info("Success! Getting access token...")
        client.publish(self.topicTVPSBasepath + "data/gettoken", '{"refreshtoken": ""}')
        client.publish(self.topicTVUIBasepath + "actions/authenticationcodeclose")

        client.subscribe(self.topicBrcsBasepath + 'ui_service/data/hotelmodechange')
        client.subscribe(self.topicMobiBasepath + 'platform_service/data/tokenissuance')

        self.wait_for_message(lambda: self.tokenissuance is None or client.cancel_loop)
        if client.cancel_loop:
            logging.error("Failed to connect to MQTT broker. Exiting...")
            client.loop_stop()
            client.disconnect()
            return

        credentials = json.loads(self.tokenissuance.payload.decode())
        credentials.update({"client_id": self.client_id, "username": self.username, "password": self.password})
        pprint(credentials)

        if debug:
            logging.info('Token issued successfully')
        with open(credentialsfile, 'w') as file:
            json.dump(credentials, file, indent=4)
        if debug:
            logging.info('Credentials saved to {credentialsfile}')        

        client.loop_stop()
        client.disconnect()

        self.accesstoken = credentials["accesstoken"]
        self.accesstoken_time = credentials["accesstoken_time"]
        self.accesstoken_duration_day = credentials["accesstoken_duration_day"]
        self.refreshtoken = credentials["refreshtoken"]
        self.refreshtoken_time = credentials["refreshtoken_time"]
        self.refreshtoken_duration_day = credentials["refreshtoken_duration_day"]
        self.client_id = credentials['client_id']
        self.username = credentials['username']
        self.password = credentials['password']
        self.authenticated = True

        return credentials["accesstoken"]

    # Load the credentials from the credentials file or generate new ones
    def load_or_generate_creds(self, rec=False):
        try:
            with open(credentialsfile, 'r') as file:
                if debug:
                    logging.info('Loading stored credentials from {credentialsfile}...')
                credentials = json.load(file)
                self.accesstoken = credentials["accesstoken"]
                self.accesstoken_time = credentials["accesstoken_time"]
                self.accesstoken_duration_day = credentials["accesstoken_duration_day"]
                self.refreshtoken = credentials["refreshtoken"]
                self.refreshtoken_time = credentials["refreshtoken_time"]
                self.refreshtoken_duration_day = credentials["refreshtoken_duration_day"]
                self.client_id = credentials['client_id']
                self.username = credentials['username']
                self.password = credentials['password']
                self.authenticated = True
        except FileNotFoundError:
            if not rec:
                if debug:
                    logging.info('No stored credentials found, starting auth with TV...')
                self.generate_creds()
                self.load_or_generate_creds(True)
            else:
                if debug:
                    logging.error('Unable to generate credentials.')
                raise

    # Show the credentials
    def show_credentials(self):
        current_time = time.time()
        print(f"Current time is {time.ctime(current_time)}")
        print("")
        print("client_id: " + self.client_id)
        print("username: " + self.username)
        print("password: " + self.password)
        print("")
        print("accesstoken: " + self.accesstoken)
        print("accesstoken_time: " + self.accesstoken_time)
        print("accesstoken_duration_day: " + str(self.accesstoken_duration_day))
        expiration_time = int(self.accesstoken_time) + (int(self.accesstoken_duration_day) * 24 * 60 * 60)
        print(f"Access Token expires at {time.ctime(expiration_time)}")
        print("")
        print("refreshtoken: " + self.refreshtoken)
        print("refreshtoken_time: " + self.refreshtoken_time)
        print("refreshtoken_duration_day: " + str(self.refreshtoken_duration_day))
        refresh_expiration_time = int(self.refreshtoken_time) + (int(self.refreshtoken_duration_day) * 24 * 60 * 60)
        print(f"Refresh Token expires at {time.ctime(refresh_expiration_time)}")
        print("")

    # Get requested information from the TV
    def get_info(self, callback_message, subscribe_topic, publish_topic):
        if debug:
            logging.info("Getting information...")
        client = self.create_mqtt_client(client_id=self.client_id, certfile=certfile, keyfile=keyfile, username=self.username, password=self.accesstoken)
        if debug:
            logging.info(f"Adding callback to {callback_message}")
        client.message_callback_add(callback_message, self.on_info)

        client.connect_async(tv_ip, 36669, 60)
        client.loop_start()

        self.wait_for_message(lambda: not client.connected_flag and not client.cancel_loop)
        if client.cancel_loop:
            logging.error("Failed to connect to MQTT broker. Exiting...")
            client.loop_stop()
            client.disconnect()
            return

        if debug:
            logging.info(f"Subscribing for {subscribe_topic}")
        # client.subscribe(subscribe_topic)
        client.subscribe([
            (subscribe_topic, 0),
            (self.topicMobiBasepath + 'ui_service/data/authentication', 0), # if authentication fails, this will return a message
        ])

        if debug:
            logging.info(f"Publishing message to {publish_topic}")
        client.publish(publish_topic, None)

        self.wait_for_message(lambda: self.info is None or client.cancel_loop)
        if client.cancel_loop:
            logging.error("Failed to connect to MQTT broker. Exiting...")
            client.loop_stop()
            client.disconnect()
            return None

        if not self.authenticated:
            if debug:
                logging.info("NOT Authenticated")
            auth.generate_creds()

        client.loop_stop()
        client.disconnect()

        if self.info:
            if debug:
                logging.info(f"Information received: {self.info}")
            return json.loads(self.info)
        else:
            logging.error("Failed to get information")
            return None

    # Send a command to the TV
    def send_command(self, publish_topic, command = None):
        if debug:
            logging.info("Sending command to TV...")
        client = self.create_mqtt_client(client_id=self.client_id, certfile=certfile, keyfile=keyfile, username=self.username, password=self.accesstoken)
        if debug:
            logging.info("No callback message needed for command sending.")

        client.connect_async(tv_ip, 36669, 60)
        client.loop_start()

        self.wait_for_message(lambda: not client.connected_flag and not client.cancel_loop)
        if client.cancel_loop:
            logging.error("Failed to connect to MQTT broker. Exiting...")
            client.loop_stop()
            client.disconnect()
            return

        if debug:
            logging.info(f"Publishing {command} command to {publish_topic}")
        client.publish(publish_topic, command)
        
        if debug:
            logging.info("Command sent.")
        client.loop_stop()
        client.disconnect()

    # Get the current state of the TV
    def get_tv_state(self):
        if debug:
            logging.info("Getting TV state...")
        get_tv_state_subscribe = self.topicBrcsBasepath + "ui_service/state"
        get_tv_state_callback = self.topicBrcsBasepath + "ui_service/state"
        get_tv_state_publish = self.topicTVUIBasepath + "actions/gettvstate"
        tv_state = self.get_info(get_tv_state_callback, get_tv_state_subscribe, get_tv_state_publish)
        return tv_state

    # Get the source list of the TV
    def get_source_list(self):
        if debug:
            logging.info("Getting source list...")
        get_source_list_callback = self.topicMobiBasepath + "ui_service/data/sourcelist"
        get_source_list_subscribe = self.topicMobiBasepath + "ui_service/data/sourcelist"
        get_source_list_publish = self.topicTVUIBasepath + "actions/sourcelist"
        source_list = self.get_info(get_source_list_callback, get_source_list_subscribe, get_source_list_publish)
        return source_list
    
    # Get the volume of the TV
    def get_volume(self):
        if debug:
            logging.info("Getting volume...")
        get_volume_callback = self.topicBrcsBasepath + "platform_service/actions/volumechange"
        get_volume_subscribe = self.topicBrcsBasepath + "platform_service/actions/volumechange"
        get_volume_publish = self.topicTVPSBasepath + "actions/getvolume"
        volume = self.get_info(get_volume_callback, get_volume_subscribe, get_volume_publish)
        return volume

    # Get the app list of the TV
    def get_app_list(self):
        if debug:
            logging.info("Getting app list...")
        get_app_list_callback = self.topicMobiBasepath + "ui_service/data/applist"
        get_app_list_subscribe = self.topicMobiBasepath + "ui_service/data/applist"
        get_app_list_publish = self.topicTVUIBasepath + "actions/applist"
        app_list = self.get_info(get_app_list_callback, get_app_list_subscribe, get_app_list_publish)
        return app_list

    # Power Cycle the TV
    def power_cycle_tv(self):
        if debug:
            logging.info("Power cycling the TV...")
        power_cycle_command = "KEY_POWER"
        power_cycle_publish = self.topicRemoBasepath + "actions/sendkey"
        self.send_command(power_cycle_publish, power_cycle_command)
        return True

    # Send KEY to the TV
    def send_key(self,key):
        if debug:
            logging.info("send key to TV..."+key)
        tv_state = auth.get_tv_state()
        if tv_state:
            if "statetype" in tv_state and tv_state["statetype"] == "fake_sleep_0":
                logging.info("TV is off. Not sending key...")
                return False
            else:
                send_key_publish = self.topicRemoBasepath + "actions/sendkey"
                self.send_command(send_key_publish, key)
                return True
        else:
            logging.error("Failed to get TV state.")
            return False

    # Change the source of the TV
    def change_source(self, source_id):
        if debug:
            logging.info(f"Changing source to {source_id}...")
        tv_state = auth.get_tv_state()
        if tv_state:
            if "statetype" in tv_state and tv_state["statetype"] == "fake_sleep_0":
                logging.info("TV is off. Not changing source...")
                return False
            else:
                logging.info("TV is on. Changing source...")
                change_source_publish = self.topicTVUIBasepath + "actions/changesource"
                change_source_command = json.dumps({"sourceid": source_id})
                self.send_command(change_source_publish, change_source_command)
                return True
        else:
            logging.error("Failed to get TV state.")
            return False

    # Change the volume of the TV
    def change_volume(self, volume):
        if debug:
            logging.info(f"Changing volume to {volume}...")
        tv_state = auth.get_tv_state()
        if tv_state:
            if "statetype" in tv_state and tv_state["statetype"] == "fake_sleep_0":
                logging.info("TV is off. Not changing volume...")
                return False
            else:
                change_volume_publish = self.topicTVPSBasepath + "actions/changevolume"
                change_volume_command = str(volume)
                self.send_command(change_volume_publish, change_volume_command)
                return True
        else:
            logging.error("Failed to get TV state.")
            return False

    # Launch an app on the TV
    def launch_app(self, app_name, app_list = None):
        if debug:
            logging.info(f"Launching app {app_name}...")

        app_id = None
        app_url = None

        if not app_list:
            app_list = self.get_app_list()
            if not app_list:
                print("Failed to get app list.")
                return False

        for app in app_list:
            if app["name"].upper() == app_name.upper():
                app_id = app["appId"]
                app_url = app["url"]
                app_name = app["name"]

        if app_id is None or app_url is None:
            print("Failed to find app in app list.")
            return False
            
        tv_state = auth.get_tv_state()
        if tv_state:
            if "statetype" in tv_state and tv_state["statetype"] == "fake_sleep_0":
                logging.info("TV is off. Not launching app...")
                return False
            else:
                launch_app_publish = self.topicTVUIBasepath + "actions/launchapp"
                launch_app_command = json.dumps({"appId": app_id, "name": app_name, "url": app_url})
                self.send_command(launch_app_publish, launch_app_command)
                return True
        else:
            logging.error("Failed to get TV state.")
            return False
    
    # Show the help message
    def show_help(self):
        print("1. Get TV State, from command line: --action getstate")
        print("2. Power Cycle TV, from command line: --action powercycle (of use poweron or poweroff which first gets the state)")
        print("3. Get Source List, from command line: --action getsourcelist")
        print("4. Change Source, from command line: --action changesource --parameter <source_name>")
        print("5. Get Volume, from command line: --action getvolume")
        print("6. Change Volume, from command line: --action changevolume --parameter <volume>")
        print("7. Get App List, from command line: --action getapplist")
        print("8. Launch App, from command line: --action launchapp --parameter <app_name>")
        print("9. Send key, from command line: --action sendkey --parameter <key>\n")

        print("C. Show Credentials, from command line: --action showcredentials")
        print("R. Refresh Token, from command line: --action refreshtoken")
        print("F. Force Refresh Token, from command line: --action forcerefresh")
        print("S. Save Credentials, from command line: --action save")
        print("L. Load Credentials, from command line: --action load")
        print("A. Authenticate, from command line: --action authenticate\n")

        print("H. Help, from command line: --action help\n")

        print("0. Exit, from command line: --action exit\n")

# Main function
if __name__ == "__main__":
    print("Initializing...")
    logging.info(f"Initializing")
    # Initialize the TVAuthenticator class
    auth = TVAuthenticator()

    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Hisense TV Control')
    parser.add_argument('--action', type=str, help='Action to perform', choices=['getstate', 'powercycle', 'poweron', 'poweroff', 'getsourcelist', 'changesource', 'getvolume', 'changevolume', 'getapplist', 'launchapp', 'sendkey', 'showcredentials', 'forcerefresh', 'refreshtoken', 'save', 'load', 'authenticate', 'help', 'exit'])
    parser.add_argument('--parameter', type=str, help='Parameter for the action')
    parser.add_argument('--debug', type=str, help='Set debug mode on or off (True/False)', choices=['True', 'False'], default='False')
    args = parser.parse_args()

    # Set debug mode
    if args.debug == "True":
        debug = True
    elif args.debug == "False":
        debug = False

    # Load or generate credentials
    auth.load_or_generate_creds()

    # Show the credentials
    auth.show_credentials()

    # Define hashes and topic paths
    auth.define_topic_paths()

    # Refresh the token if needed
    auth.check_and_refresh_token()

    # Main loop
    action = None
    while action != "0":
        if not args.action:
            print("\nChoose an action:\n")
            auth.show_help()
            action = input("Action: ")
        else:
            action = args.action

        action = action.upper()
        if debug:
            logging.info(f"Action: {action}")

        if action == "1" or action == "GETSTATE":
            # Get TV State
            tv_state = auth.get_tv_state()
            if tv_state:
                print(f"TV State: \n{json.dumps(tv_state, indent=4)}")
            else:
                print("Failed to get TV state.")

        elif action == "2" or action == "POWERCYCLE":
            # Power cycle the TV
            command_sent = auth.power_cycle_tv()
            if command_sent:
                print("Power cycle command sent.")
            else:
                print("Failed to send power cycle command.")

        elif action == "3" or action == "GETSOURCELIST":
            # Get source list
            source_list = auth.get_source_list()
            if source_list:
                print(f"Source list: \n{json.dumps(source_list, indent=4)}")
            else:
                print("Failed to get source list.")

        elif action == "4" or action == "CHANGESOURCE":
            # Change Source
            if not args.parameter:
                source_list = auth.get_source_list()
                if source_list:
                    print(f"Source list: \n{json.dumps(source_list, indent=4)}")
                    source_id = input("Enter the source ID: ")
                else:
                    print("Failed to get source list.")
            else:
                source_id = args.parameter

            source_changed = auth.change_source(source_id)
            if source_changed:
                print(f"Source changed to {source_id}")
            else:
                print("Failed to change source.")

        elif action == "5" or action == "GETVOLUME":
            # Get Volume
            volume = auth.get_volume()
            if volume:
                print(f"Volume: \n{json.dumps(volume, indent=4)}")
            else:
                print("Failed to get volume.")

        elif action == "6" or action == "CHANGEVOLUME":
            # Change Volume
            if not args.parameter:
                volume = auth.get_volume()
                if volume:
                    print(f"Volume: \n{json.dumps(volume, indent=4)}")
                    volume = input("Enter the volume level (0-100): ")
                else:
                    print("Failed to get volume.")
            else:
                volume = args.parameter

            volume_changed = auth.change_volume(volume)
            if volume_changed:
                print(f"Volume changed to {volume}")
            else:
                print("Failed to change volume.")

        elif action == "7" or action == "GETAPPLIST":
            # Get App List
            app_list = auth.get_app_list()
            if app_list:
                print(f"App list: \n{json.dumps(app_list, indent=4)}")
                print("\nApps:\n")
                for app in app_list:
                    print(app['name'])
            else:
                print("Failed to get app list.")

        elif action == "8" or action == "LAUNCHAPP":
            # Launch App
            app_list = None
            if not args.parameter:
                app_list = auth.get_app_list()
                if app_list:
                    print(f"App list: \n{json.dumps(app_list, indent=4)}")
                    app_name = input("Enter the app name to launch: ")
                else:
                    print("Failed to get app list.")
            else:
                app_name = args.parameter

            app_launched = auth.launch_app(app_name, app_list)
            if app_launched:
                print(f"App launched: {app_name}")
            else:
                print("Failed to launch app.")

        elif action == "9" or action == "SENDKEY":
            # Send key
            if not args.parameter:
                key = input("Enter the key: ")
            else:
                key = args.parameter
            key_sent = auth.send_key(key)
            if key_sent:
                print(f"Key sent {key}")
            else:
                print(f"Failed to sent key {key}")

        elif action == "C" or action == "SHOWCREDENTIALS":
            # Show credentials
            auth.show_credentials()

        elif action == "F" or action == "FORCEREFRESH":
            # Refresh token
            auth.refresh_token()
            print("Token refreshed.")

        elif action == "R" or action == "REFRESHTOKEN":
            # Refresh token
            auth.check_and_refresh_token()
            print("Token refreshed.")

        elif action == "S" or action == "SAVE":
            # Save credentials
            auth.write_token_to_creds_file()
            print("Credentials saved.")

        elif action == "L" or action == "LOAD":
            # Load credentials
            auth.load_or_generate_creds()
            print("Credentials loaded.")

        elif action == "A" or action == "AUTHENTICATE":
            # Delete credentials
            auth.generate_creds()
            print("Credentials authenticated.")

        elif action == "H" or action == "HELP":
            # Help
            auth.show_help()

        elif action == "0" or action == "EXIT":
            if debug:
                logging.info("Exiting...")
            # Exit
            break

        elif action == "POWERON":
            # Power on the TV
            print("Powering on the TV...")

            # Get TV State
            tv_state = auth.get_tv_state()
            if tv_state:
                if "statetype" in tv_state and tv_state["statetype"] == "fake_sleep_0":
                    # Power cycle the TV
                    command_sent = auth.power_cycle_tv()
                    if command_sent:
                        print("Power cycle command sent.")
                    else:
                        print("Failed to send power cycle command.")
                else:
                    print("TV is already on.")
            else:
                print("Failed to get TV state.")

        elif action == "POWEROFF":
            # Power off the TV
            print("Powering off the TV...")

            # Get TV State
            tv_state = auth.get_tv_state()
            if tv_state:
                if "statetype" in tv_state and tv_state["statetype"] != "fake_sleep_0":
                    # Power cycle the TV
                    command_sent = auth.power_cycle_tv()
                    if command_sent:
                        print("Power cycle command sent.")
                    else:
                        print("Failed to send power cycle command.")
                else:
                    print("TV is already off.")
            else:
                print("Failed to get TV state.")

        # Exit when passed from command line
        if args.action:
            if debug:
                logging.info("Command from command line done - Exiting...")
            break
