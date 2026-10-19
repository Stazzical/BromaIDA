import json
from typing import Any
from ida_netnode import netnode

class IDBState:
    """State data tied to the IDB using a netnode."""

    _NODE_NAME = "$ BromaIDA.state"
    _BLOB_TAG = ord("J")            # one-byte private label for the blob array on that node which holds our JSON
    _FORMAT = 1                     # format version, idk if it'll be useful in the future

    def _read(self) -> dict[str, Any]:
        if not netnode.exist(self._NODE_NAME):
            return {}

        raw = netnode(self._NODE_NAME).getblob(0, self._BLOB_TAG)

        try:
            data = json.loads(raw.decode("utf-8")) if raw else {}
        except ValueError:
            return {}

        if not isinstance(data, dict) or data.get("__format__") != self._FORMAT:
            # reset if format version is different
            return {}

        return data

    def _write(self, data: dict[str, Any]) -> None:
        data["__format__"] = self._FORMAT
        node = netnode(self._NODE_NAME, 0, True)
        node.setblob(
            json.dumps(data, separators=(",", ":")).encode("utf-8"), 0, self._BLOB_TAG
        )

    def has(self, key: str) -> bool:
        return key in self._read()

    def get(self, key: str, default: Any = None) -> Any:
        return self._read().get(key, default)

    def set(self, key: str, value: Any) -> None:
        data = self._read()
        data[key] = value
        self._write(data)

    def delete(self, key: str) -> None:
        data = self._read()
        if data.pop(key, None) is not None:
            self._write(data)

    def clear(self) -> None:
        if netnode.exist(self._NODE_NAME):
            netnode(self._NODE_NAME).kill()
