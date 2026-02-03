import json
import os
import splunk.admin as admin

# Location where configuration will be saved
CONFIG_FILE = os.path.join(os.path.dirname(__file__), "..", "local", "llm_config.json")

class SaveLLMConfigHandler(admin.MConfigHandler):

    def setup(self):
        # Define which arguments the REST handler will accept
        for arg in ["endpoint", "model", "temperature", "max_tokens", "timeout", "chunk_size", "analysis_mode"]:
            self.supportedArgs.addOptArg(arg)

    def handlePost(self, confInfo):
        # Collect parameters from the request
        config_data = {arg: self.callerArgs.data.get(arg, [None])[0] for arg in self.callerArgs.data}

        # Ensure the folder exists
        os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)

        # Save JSON to file
        with open(CONFIG_FILE, "w") as f:
            json.dump(config_data, f, indent=2)

        confInfo["message"] = "Configuration saved successfully."

    def handleList(self, confInfo):
        # This handles GET requests (for loading config)
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r") as f:
                data = json.load(f)
            for key, value in data.items():
                confInfo[key] = value

admin.init(SaveLLMConfigHandler, admin.CONTEXT_NONE)
