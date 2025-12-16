import getpass
import os
from typing import List, Mapping, Optional

true_values = ["1", "true", "yes"]
false_values = ["0", "false", "no"]


class ConfigError(ValueError):
    pass


class ConfigValueMissingError(ConfigError):
    pass


class ConfigInvalidDefaultError(ConfigError):
    pass


class ConfigInvalidValueError(ConfigError):
    pass


class Config:
    def __init__(self, config_map: Optional[Mapping] = None):
        self.config_map = config_map if config_map is not None else os.environ
        self.config_map = {k: str(v) for k, v in self.config_map.items()}

    def require_config(self, name: str) -> str:
        config = self.config_map.get(name)
        if config is None:
            raise ConfigValueMissingError(f"{name} isn't present in the config")
        return config

    def get_config(self, name: str, default: str) -> str:
        return self.config_map.get(name, default)

    def require_bool(self, name: str) -> bool:
        if name not in self.config_map:
            raise ConfigValueMissingError(f"{name} isn't present in the config")

        value = self.config_map[name].lower()
        if value in true_values:
            return True
        if value in false_values:
            return False

        # value isn't one of the recognized boolean values
        raise ConfigInvalidValueError(f"value of {name} is not valid boolean: '{value}'")

    def get_bool(self, name: str, default: bool) -> bool:
        # Ensure that the default is of correct type.
        if not isinstance(default, bool):
            raise ConfigInvalidDefaultError("Default value must be boolean")

        try:
            return self.require_bool(name)
        except ConfigValueMissingError:
            return default

    def require_int(self, name: str) -> int:
        if name not in self.config_map:
            raise ConfigValueMissingError(f"{name} isn't present in the config")

        value = self.config_map[name]
        try:
            return int(value)
        except ValueError as error:
            raise ConfigInvalidValueError(f"value of {name} is not valid int: '{value}'") from error

    def get_int(self, name: str, default: int) -> int:
        # Ensure that the default is of correct type.
        # As boolean inherits from integer extra check is added -> (isinstance(True, int) is True)
        if not isinstance(default, int) or isinstance(default, bool):
            raise ConfigInvalidDefaultError("Default value must be int")

        try:
            return self.require_int(name)
        except ConfigValueMissingError:
            return default

    def require_float(self, name: str) -> float:
        if name not in self.config_map:
            raise ConfigValueMissingError(f"{name} isn't present in the config")

        value = self.config_map[name]
        try:
            return float(value)
        except ValueError as err:
            raise ConfigInvalidValueError(f"value of {name} is not valid float: '{value}'") from err

    def get_float(self, name: str, default: float) -> float:
        # Ensure that the default has correct type
        if not isinstance(default, float):
            raise ConfigInvalidDefaultError("Default value must be float")
        try:
            return self.require_float(name)
        except ConfigValueMissingError:
            return default

    def require_list(self, name: str, separator: str) -> List[str]:
        if name not in self.config_map:
            raise ConfigValueMissingError(f"{name} isn't present in the config")

        value = self.config_map[name]
        try:
            return value.split(separator)
        except ValueError as err:
            raise ConfigInvalidValueError(f"value of {name} is not valid list: '{value}'") from err

    def get_list(self, name: str, separator: str, default: List[str]) -> List[str]:
        if not isinstance(default, List):
            raise ConfigInvalidDefaultError("Default value must be list")

        if not all(isinstance(item, str) for item in default):
            raise ConfigInvalidDefaultError("Default value must contain only strings")

        try:
            return self.require_list(name, separator)
        except ConfigValueMissingError:
            return default


def _get_username():
    # pylint: disable=broad-except
    username = "unknown"
    try:
        username = getpass.getuser()
    except Exception:
        pass
    return username
