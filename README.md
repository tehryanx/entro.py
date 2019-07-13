# entro.py
entro.py searches files for strings with high shannon entropy. Similar to [trufflehog](https://github.com/dxa4481/truffleHog) but for local files rather than git repos. 

## Install
```bash
git clone https://github.com/tehryanx/entro.py
```

## What it does
entro.py will dig secrets out of a file or a group of files by returning strings with high shannon entropy. This can be used to quickly pull secret keys out of a large collection of files like a local sourcecode repo. 

## How to
To use entro.py on a single file use: 
```bash
entro.py -f ./filename
```

You can also search all the files in the current directory using: 
```bash
entro.py
```

or recursively search all the files in the current directory and all of its subdirectories using: 
```bash
entro.py -r
```

By default entro.py only considers strings that are at least 20 characters long. You can adjust this using:
```bash
entro.py -m 33
```

It also only considers strings that conform either to the hexidecimal or base64 charsets. By default it will return hex strings with a shannon entropy of greater than 3 and base64 strings with a shannon entropy greater than 4.5. These values can be adjusted as follows: 

```bash
entro.py -b64entropy 5
entro.py -hexentropy 4
```
