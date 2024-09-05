# Nakamoto

Nakamoto is a 2 layer encryption tool to protect your data and your cryptocurrency private keys

## Usage

There are 3 types of usage:

- Generate random passwords

Example:

```
./nakamoto g
```

- Encrypt file

Example:

Encrypt file _myfile.txt_

```
./nakamoto enc myfile.txt
```

- Decrypt file

Decrypt file _out.nkm_

```
./nakamoto dec out.nkm
```

## Building

### Requirements

- Openssl 3.3 or later
- CMake 4.3 or later

### First time installation

You need to install Open SSL.

```sh
make install_ssl
```

**NOTE** You only need to do this step once

### Build nakamoto

```sh
make
```

## Cleaning

### Cleaning project

```
make clean
```

### Cleaning Compiled Openssl libs

```
make remove_ssl
```

Have fun :)

