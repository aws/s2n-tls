import shutil
import os
from pathlib import Path
from cryptography import x509
from cert_chain_generator import CertChainBuilder, CertConfig, ExtensionConfig, key_usage_kwargs

if os.path.isdir("cert_chains"):
    shutil.rmtree("cert_chains")
Path("cert_chains").mkdir()


# A certificate chain with no optional intent extensions.
builder = CertChainBuilder()
builder.add_cert(CertConfig())
builder.add_cert(CertConfig([
    ExtensionConfig(x509.BasicConstraints(ca=True, path_length=None))
]))
builder.add_cert(CertConfig([
    ExtensionConfig(x509.BasicConstraints(ca=True, path_length=None))
]))
chain = builder.build()
chain.write("cert_chains/no_intent")


# A leaf certificate with various fields set in the KeyUsage extension.
leaf_key_usage_fields_of_interest = [
    # May be set by client or server leaf certificates.
    {"digital_signature": True},
    {"key_agreement": True},
    {"digital_signature": True, "key_agreement": True},
    {"digital_signature": True, "content_commitment": True},
    # May be set by server leaf certificates.
    {"key_encipherment": True},
    # Not relevant for client or server leaf certificates.
    {"key_cert_sign": True},
]
for field_dict in leaf_key_usage_fields_of_interest:
    builder = CertChainBuilder()
    builder.add_cert(CertConfig([
        ExtensionConfig(x509.KeyUsage(**key_usage_kwargs(**field_dict)))
    ]))
    builder.add_cert(CertConfig([
        ExtensionConfig(x509.BasicConstraints(ca=True, path_length=None))
    ]))
    chain = builder.build()
    name = "_and_".join([field for field in field_dict])
    chain.write(f"cert_chains/ku_{name}_leaf")


# A CA certificate with various fields set in the KeyUsage extension.
ca_key_usage_fields_of_interest = [
    # May be set by CA certificates.
    {"key_cert_sign": True},
    {"key_cert_sign": True, "content_commitment": True},
    # Not relevant for CA certificates.
    {"digital_signature": True},
]
for field_dict in ca_key_usage_fields_of_interest:
    builder = CertChainBuilder()
    builder.add_cert(CertConfig())
    builder.add_cert(CertConfig([
        ExtensionConfig(x509.KeyUsage(**key_usage_kwargs(**field_dict))),
        ExtensionConfig(x509.BasicConstraints(ca=True, path_length=None)),
    ]))
    builder.add_cert(CertConfig([
        ExtensionConfig(x509.BasicConstraints(ca=True, path_length=None))
    ]))
    chain = builder.build()
    name = "_and_".join([field for field in field_dict])
    chain.write(f"cert_chains/ku_{name}_intermediate")


# A leaf/CA certificate with various fields set in the ExtendedKeyUsage extension.
extended_key_usage_fields_of_interest = [
    # May be set by client or server certificates.
    [x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH, x509.oid.ExtendedKeyUsageOID.SERVER_AUTH],
    [
        x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
        x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
        x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION,
    ],
    # May be set by client certificates.
    [x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH],
    # May be set by server certificates.
    [x509.oid.ExtendedKeyUsageOID.SERVER_AUTH],
    # Not relevant for client or server certificates.
    [x509.oid.ExtendedKeyUsageOID.CODE_SIGNING],
]
for field_list in extended_key_usage_fields_of_interest:
    # Leaf certificate with Extended Key Usage extension.
    builder = CertChainBuilder()
    builder.add_cert(CertConfig([
        ExtensionConfig(x509.ExtendedKeyUsage(field_list))
    ]))
    builder.add_cert(CertConfig([
        ExtensionConfig(x509.BasicConstraints(ca=True, path_length=None))
    ]))
    chain = builder.build()
    name = "_and_".join([field._name for field in field_list])
    chain.write(f"cert_chains/eku_{name}_leaf")

    # CA certificate with Extended Key Usage extension.
    builder = CertChainBuilder()
    builder.add_cert(CertConfig())
    builder.add_cert(CertConfig([
        ExtensionConfig(x509.ExtendedKeyUsage(field_list)),
        ExtensionConfig(x509.BasicConstraints(ca=True, path_length=None)),
    ]))
    builder.add_cert(CertConfig([
        ExtensionConfig(x509.BasicConstraints(ca=True, path_length=None))
    ]))
    chain = builder.build()
    name = "_and_".join([field._name for field in field_list])
    chain.write(f"cert_chains/eku_{name}_intermediate")


# Invalid Key Usage extension deep within the cert chain.
builder = CertChainBuilder()
builder.add_cert(CertConfig())
builder.add_cert(CertConfig([
    ExtensionConfig(x509.BasicConstraints(ca=True, path_length=None))
]))
builder.add_cert(CertConfig([
    ExtensionConfig(x509.BasicConstraints(ca=True, path_length=None))
]))
builder.add_cert(CertConfig([
    ExtensionConfig(x509.BasicConstraints(ca=True, path_length=None))
]))
builder.add_cert(CertConfig([
    # digitalSignature is not relevant for CA certificates.
    ExtensionConfig(x509.KeyUsage(**key_usage_kwargs(digital_signature=True))),
    ExtensionConfig(x509.BasicConstraints(ca=True, path_length=None)),
]))
builder.add_cert(CertConfig([
    ExtensionConfig(x509.BasicConstraints(ca=True, path_length=None))
]))
chain = builder.build()
chain.write(f"cert_chains/ku_digital_signature_intermediate_long")


# Invalid Extended Key Usage extension deep within the cert chain.
builder = CertChainBuilder()
builder.add_cert(CertConfig())
builder.add_cert(CertConfig([
    ExtensionConfig(x509.BasicConstraints(ca=True, path_length=None))
]))
builder.add_cert(CertConfig([
    ExtensionConfig(x509.BasicConstraints(ca=True, path_length=None))
]))
builder.add_cert(CertConfig([
    ExtensionConfig(x509.BasicConstraints(ca=True, path_length=None))
]))
builder.add_cert(CertConfig([
    # codeSigning is not relevant for TLS certificates.
    ExtensionConfig(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CODE_SIGNING])),
    ExtensionConfig(x509.BasicConstraints(ca=True, path_length=None)),
]))
builder.add_cert(CertConfig([
    ExtensionConfig(x509.BasicConstraints(ca=True, path_length=None))
]))
chain = builder.build()
chain.write(f"cert_chains/eku_codeSigning_intermediate_long")


# Invalid intent in non-critical KeyUsage extension.
builder = CertChainBuilder()
builder.add_cert(CertConfig([
    # crlSign is not relevant for leaf certificates.
    ExtensionConfig(x509.KeyUsage(**key_usage_kwargs(crl_sign=True)), critical=False)
]))
builder.add_cert(CertConfig([
    ExtensionConfig(x509.BasicConstraints(ca=True, path_length=None))
]))
chain = builder.build()
chain.write(f"cert_chains/ku_crl_sign_leaf_non_critical")


# Invalid intent in non-critical ExtendedKeyUsage extension.
builder = CertChainBuilder()
builder.add_cert(CertConfig([
    # codeSigning is not relevant for TLS certificates.
    ExtensionConfig(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CODE_SIGNING]), critical=False),
]))
builder.add_cert(CertConfig([
    ExtensionConfig(x509.BasicConstraints(ca=True, path_length=None))
]))
chain = builder.build()
chain.write(f"cert_chains/eku_code_signing_intermediate_non_critical")


# Invalid intent in the root cert.
builder = CertChainBuilder()
builder.add_cert(CertConfig())
builder.add_cert(CertConfig([
    # emailProtection is not relevant for TLS certificates.
    ExtensionConfig(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION])),
    ExtensionConfig(x509.BasicConstraints(ca=True, path_length=None)),
]))
chain = builder.build()
chain.write(f"cert_chains/eku_email_protection_root")


# An intermediate certificate with an invalid BasicConstraints extension.
builder = CertChainBuilder()
builder.add_cert(CertConfig())
builder.add_cert(CertConfig([
    # A certificate with the CA field set to false should not be used to sign other certificates.
    ExtensionConfig(x509.BasicConstraints(ca=False, path_length=None)),
]))
builder.add_cert(CertConfig([
    ExtensionConfig(x509.BasicConstraints(ca=True, path_length=None)),
]))
chain = builder.build()
chain.write(f"cert_chains/bc_non_ca_intermediate")
