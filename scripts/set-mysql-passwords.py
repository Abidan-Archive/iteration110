"""Change local account passwords without putting secrets in argv or logs."""

import pathlib
import subprocess
import sys


def password_sql(user, password):
    # Fix the session mode so backslashes remain literal. SQL-standard doubled
    # quotes then handle all password punctuation, independently of global mode.
    if "\0" in user or "\0" in password:
        raise ValueError("NUL is not supported in database credentials")
    user = user.replace("'", "''")
    password = password.replace("'", "''")
    return (
        "SET SESSION sql_mode = 'NO_BACKSLASH_ESCAPES';\n"
        f"ALTER USER '{user}'@'localhost' IDENTIFIED BY '{password}';\n"
    )


def main():
    mysql, *accounts = sys.argv[1:]
    for user, path in zip(accounts[::2], accounts[1::2], strict=True):
        password = pathlib.Path(path).read_text().rstrip("\n")
        result = subprocess.run(
            [mysql, "--batch", "--binary-mode", "--default-character-set=utf8mb4"],
            input=password_sql(user, password).encode(),
            capture_output=True,
            check=False,
        )
        # The client may echo SQL on errors. Never forward its output to journald.
        if result.returncode:
            raise RuntimeError("Database password update failed; check local account availability")


if __name__ == "__main__":
    main()
