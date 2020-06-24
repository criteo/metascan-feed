# Metascan Feed

The repository aims to collect all vulnerability tests written at Criteo.
Those scripts share specific output formating used by metascan.

## Contribute

Metascan is using custom NMap nse scripts to detect vulnerabilities.
Those scripts are using a common parsable output format.

## License

This project is released under Apache 2.0 license.

## Languages

Metascan aims to allow anyone to write checks with ease in any supported
scripting language.

Currently only nse scripts are supported. It uses an embedded DSL in Lua.

In the end, Metascan will list the available scripts and run them as
part of its continuous scans in order to ensure non-regression and
find new vulnerabilities.

### NSE

NSE stands for Nmap Scripting Engine. It's used to write scripts
doing service discovery and vulnerability checks in Lua and make them
executable by Nmap depending on the efficient port discovery performed
by Nmap.

For more information, you can start reading the following documentation
https://nmap.org/book/nse.html and read a tutorial about Lua like this
one https://www.tutorialspoint.com/lua/.
