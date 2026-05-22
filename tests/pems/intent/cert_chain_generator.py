import datetime
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization


class ExtensionConfig:
    def __init__(self, extension: x509.ExtensionType, critical: bool = True):
        self.extension = extension
        self.critical = critical


class CertConfig:
    def __init__(self, extensions: [ExtensionConfig] = []):
        self.extensions = extensions
        self.private_key = ec.generate_private_key(ec.SECP256R1())


class CertChainBuilder:
    class _CertAndKey:
        def __init__(self, name: str, cert: x509.Certificate, private_key: ec.EllipticCurvePrivateKey):
            self.name = name
            self.cert = cert
            self.private_key = private_key

    class _CertChain:
        def __init__(self, cert_chain: ["CertChainBuilder._CertAndKey"]):
            self.cert_chain = cert_chain

        def write(self, cert_dir: str):
            assert len(self.cert_chain) > 0
            Path(cert_dir).mkdir(exist_ok=True)

            # Write each individual certificate to its own pem. This allows the trust store to be
            # customized with specific certificates.
            for i, cert_and_key in enumerate(self.cert_chain):
                with open(f"{cert_dir}/{cert_and_key.name}-cert.pem", "wb") as f:
                    f.write(cert_and_key.cert.public_bytes(encoding=serialization.Encoding.PEM))

            # Write the certificate chain to be sent in the TLS handshake to a pem, which can omit
            # the root certificate.
            with open(f"{cert_dir}/cert-chain.pem", "wb") as f:
                cert_chain_without_root = self.cert_chain[:-1]
                for cert_and_key in cert_chain_without_root:
                    f.write(cert_and_key.cert.public_bytes(encoding=serialization.Encoding.PEM))

            # Write the leaf private key to a pem.
            leaf = self.cert_chain[0]
            with open(f"{cert_dir}/{leaf.name}-key.pem", "wb") as f:
                f.write(leaf.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                ))

    def __init__(self):
        self._configs: [CertConfig] = []

    def add_cert(self, config: CertConfig):
        self._configs.append(config)

    def build(self) -> _CertChain:
        assert len(self._configs) > 0

        issuer_name = self._x509_name("root")
        issuer_key = self._configs[0].private_key

        cert_chain = []

        # Build the chain from the root to the leaf.
        for i, config in enumerate(reversed(self._configs)):
            builder = x509.CertificateBuilder()

            if i == 0:
                name = "root"
            elif i < len(self._configs) - 1:
                name = f"intermediate_{i}"
            else:
                name = "leaf"
            subject_name = self._x509_name(name)
            builder = builder.subject_name(subject_name)

            builder = builder.issuer_name(issuer_name)
            builder = builder.public_key(config.private_key.public_key())
            builder = builder.serial_number(x509.random_serial_number())
            builder = builder.not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            builder = builder.not_valid_after(
                datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365*100)
            )

            # Add some extensions by default, to avoid specifying them in every ExtensionBuilder.
            builder = builder.add_extension(
                x509.SubjectKeyIdentifier.from_public_key(config.private_key.public_key()),
                critical=False,
            )
            builder = builder.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
                critical=False,
            )
            if name == "leaf":
                builder = builder.add_extension(
                    x509.SubjectAlternativeName([x509.DNSName("localhost")]),
                    critical=False,
                )

            for extension_config in config.extensions:
                builder = builder.add_extension(extension_config.extension, extension_config.critical)

            cert_and_key = self._CertAndKey(
                name,
                builder.sign(issuer_key, hashes.SHA256()),
                config.private_key,
            )
            # Insert at the front of the list to allow the final certificate chain to start from
            # the leaf and end at the root.
            cert_chain.insert(0, cert_and_key)

            issuer_name = subject_name
            issuer_key = config.private_key

        return self._CertChain(cert_chain)

    @staticmethod
    def _x509_name(common_name: str):
        return x509.Name([
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, "Massachusetts"),
            x509.NameAttribute(x509.NameOID.LOCALITY_NAME, "Boston"),
            x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "s2n"),
            x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name),
        ])


def key_usage_kwargs(**kwargs):
    """
    The cryptography.x509.KeyUsage constructor takes a mandatory argument for each KeyUsage field.
    Rather than specify each field when creating each KeyUsage extension, have each field default
    to False, and only specify fields that will be set to True.
    """
    kwargs_dict = {
        "digital_signature": False,
        "content_commitment": False,
        "key_encipherment": False,
        "data_encipherment": False,
        "key_agreement": False,
        "key_cert_sign": False,
        "crl_sign": False,
        "encipher_only": False,
        "decipher_only": False,
    }
    for key in kwargs:
        assert key in kwargs_dict

    kwargs_dict.update(kwargs)
    return kwargs_dict
