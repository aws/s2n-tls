import os
import select
import selectors
import subprocess
import threading

from common import Results, TimeoutException
from time import monotonic as _time


_PopenSelector = selectors.PollSelector
_PIPE_BUF = getattr(select, 'PIPE_BUF', 512)


class _processCommunicator(object):
    """
    This class allows greater control over stdin than using Popen.communicate().
    Popen.communicate() closes stdin as soon as data is written. This causes
    TLS clients (OpenSSL derivatives) to shut down before the handshake is complete.

    To prevent a premature shutdown, we need to wait until the handshake is complete
    before writing to stdin. To accomplish this we `poll` stdout for a ready_to_send
    marker. Once that marker is found, we can write input data to stdin. The
    benefit of using `poll` and `os.read` is that we get non-blocking IO. Our timeouts
    are much more reliable, and we don't risk deadlocking on a readline() call which
    will never complete.

    Another method is to read stdout line by line. This removes a lot of code that
    registers and unregisters file descriptors with a selector. It would make reading
    and writing sequential (as opposed to event based), which can be easier to read
    and maintain. The downsides with this method exist in the current integration test
    framework. We rely on sleeps and waits, and still hit hard to debug deadlocks from
    time to time.
    """
    def __init__(self, proc):
        self.proc = proc
        self.ready_to_send = None
        self.wait_for_marker = None

        # If the process times out, communicate() is called once more to pick
        # up any data remaining in stdout/stderr. This flags lets us know if
        # we need to do initial setup on the file descriptors, or if it was done
        # during the initial call.
        self._communication_started = False

    def wait_for(self, wait_for_marker, timeout=None):
        self.wait_for_marker = wait_for_marker
        stdout = None
        stderr = None

        try:
            stdout, stderr = self._communicate(None, timeout)
        finally:
            self._communication_started = True

        return (stdout, stderr)

    def communicate(self, input_data=None, ready_to_send=None, wait_for_marker=None, timeout=None):
        self.ready_to_send = ready_to_send
        stdout = None
        stderr = None

        try:
            stdout, stderr = self._communicate(input_data, timeout)
        finally:
            self._communication_started = True

        return (stdout, stderr)

    def _communicate(self, input_data=None, timeout=None):
        """
        This method will read and write data to a subprocess in a non-blocking manner.
        The code is heavily based on Popen.communicate. There are a couple differences:

            * STDIN is not registered for events until the read_to_send marker is found
            * STDIN is only closed after all registered events have been processed (including
              pending stdout/stderr events, allowing more data to be stored).
        """
        if self.proc.stdin:
            # Flush stdio buffer.  This might block, if the user has
            # been writing to .stdin in an uncontrolled fashion.
            try:
                self.proc.stdin.flush()
            except BrokenPipeError:
                pass  # communicate() must ignore BrokenPipeError.

        # The process' stdout and stderr are stored in a map, with two variable
        # pointing to the file objects. This allows us to include stdout/stderr
        # data in a timeout exception.
        if not self._communication_started:
            self._fileobj2output = {}
            if self.proc.stdout:
                self._fileobj2output[self.proc.stdout] = []
            if self.proc.stderr:
                self._fileobj2output[self.proc.stderr] = []

        stdout = self._fileobj2output[self.proc.stdout]
        stderr = self._fileobj2output[self.proc.stderr]

        # Data destined for stdin is stored in a memoryview and the offset
        # will be used incase multiple writes are needed.
        if input_data:
            input_view = memoryview(input_data)
        input_data_offset = 0
        input_data_sent = False

        # Keeping track of the original timeout value, and the expected end
        # time of the operation allow us to timeout while reads/writes are
        # still pending. It also allows us to only wait for the remainder of
        # the timeout after reads/writes have completed.
        orig_timeout = timeout
        if timeout is not None:
            endtime = _time() + timeout
        else:
            endtime = None

        with _PopenSelector() as selector:
            if self.proc.stdout and not self.proc.stdout.closed:
                selector.register(self.proc.stdout, selectors.EVENT_READ)
            if self.proc.stderr and not self.proc.stderr.closed:
                selector.register(self.proc.stderr, selectors.EVENT_READ)

            while selector.get_map():
                timeout = self._remaining_time(endtime)
                if timeout is not None and timeout < 0:
                    self._check_timeout(endtime, orig_timeout,
                                        stdout, stderr,
                                        skip_check_and_raise=True)
                    raise RuntimeError(  # Impossible :)
                        '_check_timeout(..., skip_check_and_raise=True) '
                        'failed to raise TimeoutExpired.')

                ready = selector.select(timeout)
                self._check_timeout(endtime, orig_timeout, stdout, stderr)

                for key, events in ready:
                    # STDIN is only registered to receive events after the ready-to-send
                    # marker is found.
                    if key.fileobj is self.proc.stdin:
                        chunk = input_view[input_data_offset :
                                           input_data_offset + _PIPE_BUF]
                        try:
                            input_data_offset += os.write(key.fd, chunk)
                        except BrokenPipeError:
                            selector.unregister(key.fileobj)
                        else:
                            if input_data_offset >= len(input_data):
                                selector.unregister(key.fileobj)
                                input_data_sent = True
                    elif key.fileobj in (self.proc.stdout, self.proc.stderr):
                        data = os.read(key.fd, 32768)
                        if not data:
                            selector.unregister(key.fileobj)

                        # fileobj2output[key.fileobj] is a list of data chunks
                        # that get joined later
                        self._fileobj2output[key.fileobj].append(data)

                        # If we are looking for, and find, the ready-to-send marker, then
                        # register STDIN to receive events. If there is no data to send,
                        # just mark input_send as true so we can close out STDIN.
                        if self.ready_to_send is not None and self.ready_to_send in str(data):
                            if self.proc.stdin and input_data:
                                selector.register(self.proc.stdin, selectors.EVENT_WRITE)
                            else:
                                input_data_sent = True

                        if self.wait_for_marker is not None and self.wait_for_marker in str(data):
                            selector.unregister(self.proc.stdout)
                            selector.unregister(self.proc.stderr)
                            return None, None

                # If we have finished sending all our input, and have received the
                # ready-to-send marker, we can close out stdin.
                if self.proc.stdin and input_data_sent:
                    self.proc.stdin.close()

        self.proc.wait(timeout=self._remaining_time(endtime))

        # All data exchanged.  Translate lists into strings.
        if stdout is not None:
            stdout = b''.join(stdout)
        if stderr is not None:
            stderr = b''.join(stderr)

        return (stdout, stderr)

    def _remaining_time(self, endtime):
        """Convenience for _communicate when computing timeouts."""
        if endtime is None:
            return None
        else:
            return endtime - _time()

    def _check_timeout(self, endtime, orig_timeout, stdout_seq, stderr_seq,
                       skip_check_and_raise=False):
        """
        Convenience for checking if a timeout has expired.

        NOTE: This method is included here to prevent our custom _communicate method
        from relying on a particular version of Python.
        """
        if endtime is None:
            return
        if skip_check_and_raise or _time() > endtime:
            raise subprocess.TimeoutExpired(
                    self.proc.args, orig_timeout,
                    output=b''.join(stdout_seq) if stdout_seq else None,
                    stderr=b''.join(stderr_seq) if stderr_seq else None)


class ManagedProcess(threading.Thread):
    """
    A ManagedProcess is a thread that monitors a subprocess.
    This class provides a single place to control process timeouts and cleanup.

    The stdin/stdout/stderr and exist code a monitored and results
    are made available to the caller.
    """
    def __init__(self, cmd_line, provider_set_ready_condition, wait_for_marker=None, ready_to_send=None, timeout=5, data_source=None):
        threading.Thread.__init__(self)
        self.cmd_line = cmd_line
        self.timeout = timeout
        self.results_condition = threading.Condition()
        self.ready_condition = threading.Condition()
        self.results = None
        self.process_ready = False
        self.provider_set_ready_condition = provider_set_ready_condition

        # Note: use this to set the ready condition correctly
        self.ready_to_test = wait_for_marker

        # We always need some data for stdin, otherwise .communicate() won't setup the input
        # descriptor for the process. This causes some SSL providers to close the connection
        # immediately upon creation.
        self.data_source = None
        self.ready_to_send = None
        if data_source is not None:
            self.data_source = data_source
            self.ready_to_send = ready_to_send

    def run(self):
        with self.results_condition:
            try:
                proc = subprocess.Popen(self.cmd_line, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
                self.proc = proc
            except Exception as ex:
                self.results = Results(None, None, None, ex)
                raise ex

            communicator = _processCommunicator(proc)
            if self.ready_to_test is not None:
                # We can read stdout here looking for a ready marker
                communicator.wait_for(self.ready_to_test, timeout=self.timeout)

            self.provider_set_ready_condition()

            # Result should be available to the whole scope
            proc_results = None

            try:
                proc_results = communicator.communicate(input_data=self.data_source, ready_to_send=self.ready_to_send, timeout=self.timeout)
                self.results = Results(proc_results[0], proc_results[1], proc.returncode, None)
            except subprocess.TimeoutExpired as ex:
                proc.kill()
                wrapped_ex = TimeoutException(ex)

                # Read any remaining output
                proc_results = communicator.communicate()
                self.results = Results(proc_results[0], proc_results[1], proc.returncode, wrapped_ex)
            except Exception as ex:
                self.results = Results(None, None, None, ex)
                raise ex
            finally:
                # This data is dumped to stdout so we capture this
                # information no matter where a test fails.
                print("Command line: {}".format(" ".join(self.cmd_line)))
                print(f"Exit code: {proc.returncode}")
                print(f"Stdout: {proc_results[0]}")
                print(f"Stderr: {proc_results[1]}")

    def _process_ready(self):
        """Condition variable predicate"""
        return self.process_ready is True

    def _results_ready(self):
        """Condition variable predicate"""
        return self.results is not None

    def get_cmd_line(self):
        return self.cmd_line

    def launch(self):
        """
        This method must be implemented by the subclass.
        It should call the run function.
        """
        raise NotImplementedError

    def get_results(self, send_data=None):
        """
        Block until the results are ready, or a timeout is reached.
        Return the results, or raise the timeout exception.
        """
        with self.results_condition:
            result = self.results_condition.wait_for(self._results_ready, timeout=self.timeout)

            if result is False:
                raise Exception("Timeout")

        yield self.results
