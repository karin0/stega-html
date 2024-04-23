# stega-html

Encrypt HTML files using AES-256-GCM into self-contained HTML files.

## Usage

Assuming a static site is in the `site` directory:

```console
$ python stega.py --keygen > key             # Generate a key
$ cp -r site site_bak                        # Make a backup
$ shopt -s globstar                          # Enable recursive globbing
$ python stega.py -e key -mi site/**/*.html  # All HTML files are encrypted in place!
$ cp decrypt.js site/                        # Add the decryption script
$ serve site                                 # Serve the static site
```

Note that only the HTML files are encrypted, and all the other assets (CSS, JS, images) will be served as is.
