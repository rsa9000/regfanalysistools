regfanalysistools: low-level MS Windows registry files analysis
===============================================================

More information about internal regf files format:

 * https://github.com/libyal/libregf/blob/master/documentation/Windows%20NT%20Registry%20File%20(REGF)%20format.asciidoc
 * https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md

Features
--------

This set of utils is designed primarily for analysis of the corrupted
registry files.

Each utility shows file content from own point of view:

 * as a container of elements of variable length, where some elements could
   contain links to other elements
 * as as tree of keys and values with more or less detailed info about each
   of them

Besides of main analysis work each utility verifies data consistency by
checking for orphaned cells, cells with multiple reference, required minimum
cell size, cell signatures, etc.

The following OS(s) are tested/supported:

 * FreeBSD
 * GNU/Linux

Installation
------------

To build utils from sources just run as regular user:

    $ make

and to install them, run the following command as privileged user:

    # make install

Usage
-----

Package contains few utils:

 * regfdump - dumps registry file in element by element manner independently
   of logical tree structure
 * regfwalk - walk over the registry tree and print every portion of info
   about each founded element
 * regftree - lite version of regfwalk: print only logical tree structure
   (keys hierarchy) and values

Each utils require only registry filename as command line argument. Main data
printed to STDOUT, while error/warning messages printed to STDERR.

Examples:

    $ regfdump WIDNOWS/system32/config/SYSTEM

or

    $ regfwalk WINDOWS/system32/config/SOFTWARE

or

    $ regftree WINDOWS/system32/config/SOFTWARE

TODO
----

 * make utils more resistant to corrupted input files
 * add internal help

License
-------

This project is licensed under the terms of the ISC license. See
the LICENSE file for license rights and limitations.
