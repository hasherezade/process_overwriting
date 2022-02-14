# Process Overwriting
[![Build status](https://ci.appveyor.com/api/projects/status/ehmf01f38h5ce8ri?svg=true)](https://ci.appveyor.com/project/hasherezade/libpeconv-tpl)
[![Last Commit](https://img.shields.io/github/last-commit/hasherezade/libpeconv_tpl/master)](https://github.com/hasherezade/libpeconv_tpl/commits)

Process Overwriting is a PE injection technique, closely related to [Process Hollowing](https://github.com/hasherezade/libpeconv/tree/master/run_pe).

Process Hollowing (aka RunPE) is an old and popular PE injection technique. It comes in has variety of flavors, but there are some steps in common:
1. Start by creating a process in a suspended state
2. Write our own PE module in its memory
3. Redirect to the new module
4. Resume the thread

Process Hollowing does not require manual loading of payload's imports. Thanks to the step 3 Windows loader treat our PE implant as the main module of the process, and will load imports automatically when its execution resume.

To make our implant recognized by Windows loader, its module base must be filled in PEB. It is usually done by one of the two ways:
+ in the most classic variant, the original PE is unmapped from memory, and the new PE is mapped on its place, at the same address.
+ in another, yet common variant, the old module is left as is, and another PE is mapped in a new memory region. Then the new module is then manually written to PEB


Clone:
-
Use recursive clone to get the repo together with all the submodules:
```console
git clone --recursive https://github.com/hasherezade/process_overwriting.git
```
