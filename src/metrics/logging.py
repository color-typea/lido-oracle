import json
import logging
import os

LOGLEVEL = os.environ.get('LOGLEVEL', 'INFO').upper()

class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        message = record.msg if isinstance(record.msg, dict) else {'msg': record.getMessage()}

        if 'value' in message:
            message['value'] = str(message['value'])

        to_json_msg = json.dumps({
            'name': record.name,
            'levelname': record.levelname,
            'funcName': record.funcName,
            'lineno': record.lineno,
            'module': record.module,
            'pathname': record.pathname,
            **message,
        })
        return to_json_msg


handler = logging.StreamHandler()
handler.setFormatter(JsonFormatter())

logging.basicConfig(
    level=LOGLEVEL,
    handlers=[handler],
)
