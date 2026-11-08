"""Bounded subprocess execution for analysis tools; no shell or sample launch."""
import os
import signal
import subprocess
from pathlib import Path


def run_bounded(command, directory, timeout=120, max_output_bytes=16777216, memory_mb=2048):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    stdout, stderr = directory / 'stdout.log', directory / 'stderr.log'

    def limits():
        import resource
        resource.setrlimit(resource.RLIMIT_FSIZE, (max_output_bytes, max_output_bytes))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_CPU, (int(timeout) + 1, int(timeout) + 2))
        if memory_mb:
            size = int(memory_mb) * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (size, size))

    result = {'command': [str(x) for x in command], 'status': 'failed'}
    environment = os.environ.copy()
    # Native math libraries must not multiply worker threads and virtual-memory use.
    environment.update(OPENBLAS_NUM_THREADS='1', OMP_NUM_THREADS='1', MKL_NUM_THREADS='1')
    with stdout.open('wb') as out, stderr.open('wb') as err:
        try:
            proc = subprocess.Popen(command, stdout=out, stderr=err, stdin=subprocess.DEVNULL,
                                    start_new_session=True, env=environment,
                                    preexec_fn=limits if os.name == 'posix' else None)
            try:
                code = proc.wait(timeout=timeout)
                result.update(returncode=code, status='completed' if code == 0 else 'failed')
            except subprocess.TimeoutExpired:
                result['status'] = 'timeout'
            finally:
                # Also clean up descendants that survived after their parent exited.
                if os.name == 'posix':
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                elif proc.poll() is None:
                    proc.kill()
                proc.wait()
        except OSError as exc:
            result.update(status='unavailable', error=str(exc))
    result['stdout_bytes'] = stdout.stat().st_size
    result['stderr_bytes'] = stderr.stat().st_size
    if max(result['stdout_bytes'], result['stderr_bytes']) >= max_output_bytes:
        result['status'] = 'output_limit'
    return result
