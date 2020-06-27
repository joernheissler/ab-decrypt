Android Backup Decryptor
========================
Decryptor for android backups that were created with ``adb backup``.

Installation
------------
.. code-block:: bash

    python3 -m venv /path/to/venv
    /path/to/venv/pip install ab-decrypt
    ln -sr /path/to/venv/ab-decrypt ~/bin/

Usage
-----
.. code-block:: bash

    # Read from stdin, write to stdout
    $ ab-decrypt

    # Read from stdin, write to stdout
    $ ab-decrypt - -

    # Read from file, write to other file
    $ ab-decrypt backup.ab backup.tar

    # List backup contents
    $ ab-decrypt backup.ab | tar -tv

Environment variables
---------------------
* ``AB_DECRYPT_PASSWORD``: Decryption password

Help / Bugs / Contributions
---------------------------
Please file an issue or pull request at GitHub.
