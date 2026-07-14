"""Application settings decoy (corpus negative).

A Python class whose attributes echo openssl.cnf key names. The config scanner
must not classify Python source as an openssl.cnf: there is no INI [section]
header (``class TLS:`` is not one) and the value is a quoted string literal,
not an unquoted protocol token.
"""


class TLS:
    MinProtocol = "TLSv1.2"
    CipherString = "DEFAULT@SECLEVEL=2"
    enabled = True
