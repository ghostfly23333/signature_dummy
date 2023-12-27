Signature Test Repo
===================

This is a test repo for the signature feature.

Here is how it works:

1.  You create a key pair with `key_generator.py`, it will create 2 files:
    `private.pem` and `public.pem`.
2.  copy `private.pem` to client, and `public.pem` to server.
3.  client use `client.py` to send the message in `message` to server.
4.  server use `server.py` to receive the message, and verify the signature. The signature verification has 2 steps:
    1.  verify the signature with `public.pem` to make sure the key pair is correct.
    2.  verify the timestamp in the message to make sure the message is not replayed.

5. when the signature is verified, the server will print the message to the console.

There are 2 valid operations in client.py:

1. `action:send_msg`, the value should be the string you want to send to server.
2. `action:chg_pwd`, the value should be the new_password you want to change to. The new password also will store in `password.txt` in client side.