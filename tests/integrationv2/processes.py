import os
import time
import threading
import subprocess
from common import Results, TimeoutException


class ManagedProcess(threading.Thread):
    """
    A ManagedProcess is a thread that monitors a subprocess.
    This class provides a single place to control process timeouts and cleanup.

    The stdin/stdout/stderr and exist code a monitored and results
    are made available to the caller.
    """
    def __init__(self, cmd_line, provider_set_ready_condition, timeout, data_source=None):
        threading.Thread.__init__(self)
        self.cmd_line = cmd_line
        self.timeout = timeout
        self.results_condition = threading.Condition()
        self.ready_condition = threading.Condition()
        self.results = None
        self.process_ready = False
        self.provider_set_ready_condition = provider_set_ready_condition

        # We always need some data for stdin, otherwise .communicate() won't setup the input
        # descriptor for the process. This causes some SSL providers to close the connection
        # immediately upon creation.
        self.data_source = b"A few test bytes"
        if data_source is not None:
            self.data_source = data_source

    def run(self):
        with self.results_condition:
            try:
                proc = subprocess.Popen(self.cmd_line, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
            except Exception as ex:
                self.results = Results(None, None, None, ex)
                raise ex

            self.provider_set_ready_condition()

            # Result should be available to the whole scope
            proc_results = None
            try:
                # If the process' stdin is set, input *must* be provided. Otherwise stdin is closed
                # almost immediately. This causes some SSL providers to close the connection before
                # the s2n client can complete.
                proc_results = proc.communicate(input=self.data_source, timeout=self.timeout)
                self.results = Results(proc_results[0], proc_results[1], proc.returncode, None)
            except subprocess.TimeoutExpired as ex:
                proc.kill()
                wrapped_ex = TimeoutException(ex)

                # Read any remaining output
                proc_results = proc.communicate()
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
