"""Bounded QMP client used only inside the private managed lab."""
import json
import socket
import time


def execute(path, command, arguments=None, timeout=15):
    deadline = time.monotonic() + timeout
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(timeout)
        connection.connect(str(path))
        with connection.makefile('rwb', buffering=0) as stream:
            def receive():
                connection.settimeout(max(0.01, deadline - time.monotonic()))
                line = stream.readline(1048577)
                if not line or len(line) > 1048576:
                    raise RuntimeError('Missing or oversized QMP response')
                return json.loads(line)
            greeting = receive()
            if 'QMP' not in greeting:
                raise RuntimeError('Invalid QMP greeting')
            for identifier, name, args in ((1, 'qmp_capabilities', None), (2, command, arguments)):
                request = {'execute': name, 'id': identifier}
                if args is not None:
                    request['arguments'] = args
                stream.write(json.dumps(request).encode() + b'\n')
                while True:
                    response = receive()
                    if response.get('id') != identifier:
                        continue
                    if 'error' in response:
                        raise RuntimeError(f'QMP {name} failed: {response["error"]}')
                    if 'return' not in response:
                        raise RuntimeError('QMP response lacks return value')
                    break
            return response['return']
