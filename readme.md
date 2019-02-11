This is a utility to accompany the bitnami [sealed-secrets](https://github.com/bitnami-labs/sealed-secrets) controller.

I found it tedious to manually construct secrets on disk with base64 encoded data, just to generate a sealed secret and throw away the source. I also use a pre-saved public key instead of using `kubeseal`'s direct connection functionality.

This is a simple little web form that accepts some basic data about your secret, and its keys and values. It will encode the secret in-browser using the public key, and print a yaml `SealedSecret` you can copy and deploy.

All crypto is done in-browser with the exact same crypto code from the controller. Compiled with gopherjs. Viewing the source shuld verify there are no schenanigans going on. There should be no external requests of any kind.

Public key is stored in browser local storage for convenience.
