import importlib.util
import pathlib
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location(
    "passwords", pathlib.Path(__file__).resolve().parents[1] / "scripts/set-mysql-passwords.py"
)
passwords = importlib.util.module_from_spec(spec)
spec.loader.exec_module(passwords)


class PasswordSQLTest(unittest.TestCase):
    def test_quotes_backslashes_unicode_and_sql_metacharacters_remain_literal(self):
        secret = "quote' backslash\\ dollar$ ; --\n雪"
        sql = passwords.password_sql("test'user", secret)
        self.assertEqual(
            sql,
            "SET SESSION sql_mode = 'NO_BACKSLASH_ESCAPES';\n"
            "ALTER USER 'test''user'@'localhost' IDENTIFIED BY "
            "'quote'' backslash\\ dollar$ ; --\n雪';\n",
        )

    def test_nul_is_rejected(self):
        with self.assertRaises(ValueError):
            passwords.password_sql("user", "bad\0password")

    def test_client_uses_stdin_and_does_not_forward_secret_bearing_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "password"
            secret = "synthetic-secret'\\value"
            path.write_text(secret + "\n")
            with mock.patch.object(passwords.sys, "argv", ["helper", "mysql", "user", str(path)]):
                with mock.patch.object(passwords.subprocess, "run") as run:
                    run.return_value = subprocess.CompletedProcess([], 1, secret.encode(), secret.encode())
                    with self.assertRaises(RuntimeError) as error:
                        passwords.main()
                    self.assertNotIn(secret, str(error.exception))
                    args, kwargs = run.call_args
                    self.assertNotIn(secret, " ".join(args[0]))
                    self.assertEqual(kwargs["input"], passwords.password_sql("user", secret).encode())
                    self.assertTrue(kwargs["capture_output"])


@unittest.skipUnless(shutil.which("mariadbd"), "MariaDB is required for integration tests")
class PasswordIntegrationTest(unittest.TestCase):
    def test_rotation_against_a_disposable_socket_only_database(self):
        with tempfile.TemporaryDirectory(prefix="mysql-password-test-") as directory:
            root = pathlib.Path(directory)
            data = root / "data"
            subprocess.run(
                ["mariadb-install-db", f"--datadir={data}",
                 "--auth-root-authentication-method=normal", "--skip-test-db"],
                check=True, capture_output=True,
            )
            server = subprocess.Popen(
                ["mariadbd", "--no-defaults", f"--datadir={data}",
                 f"--socket={root / 'socket'}", f"--pid-file={root / 'pid'}",
                 f"--log-error={root / 'error.log'}", "--skip-networking",
                 "--innodb-buffer-pool-size=32M"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            client = ["mariadb", "--no-defaults", "--user=root",
                      f"--socket={root / 'socket'}", "--batch", "--skip-column-names",
                      "--binary-mode", "--default-character-set=utf8mb4"]
            try:
                for _ in range(100):
                    ready = subprocess.run(client, input=b"SELECT 1;", capture_output=True)
                    if ready.returncode == 0:
                        break
                    self.assertIsNone(server.poll())
                    time.sleep(0.1)
                else:
                    self.fail("Disposable database did not start")
                subprocess.run(client, input=b"CREATE USER 'rotation-test'@'localhost';",
                               capture_output=True, check=True)
                for secret in ["plain", "quo'te", "back\\slash", "'; DROP USER root; --", "雪\nline"]:
                    result = subprocess.run(
                        client, input=passwords.password_sql("rotation-test", secret).encode(),
                        capture_output=True,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr.decode())
                    # Compare the server's authentication hash to its own PASSWORD()
                    # result for the original bytes, not another quoted SQL literal.
                    check = (
                        "SELECT JSON_VALUE(Priv, '$.authentication_string') = "
                        f"PASSWORD(CONVERT(0x{secret.encode().hex()} USING utf8mb4)) "
                        "FROM mysql.global_priv WHERE User = 'rotation-test';"
                    )
                    result = subprocess.run(client, input=check.encode(), capture_output=True, check=True)
                    self.assertEqual(result.stdout.strip(), b"1")
            finally:
                server.terminate()
                server.wait(timeout=15)


if __name__ == "__main__":
    unittest.main()
