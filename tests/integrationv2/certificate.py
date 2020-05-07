from constants import TEST_CERT_DIRECTORY


class Cert():
    def __init__(self, name, prefix, location=TEST_CERT_DIRECTORY):
        self.name = name
        self.cert = location + prefix + "_cert.pem"
        self.key = location + prefix + "_key.pem"

    def __str__(self):
        return self.name
