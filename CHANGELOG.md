# Unreleased
- In the `-k` mode the program now checks if the `-p` publickey is the addition of 10 or more distinct generated publickeys, every generated publickey is used at most once and all the `-n` keys are generated before the search
- Added the `-m number` parameter for the `-k` mode, it sets the minimum number of distinct generated publickeys that must be added, it is 10 by default and `-m 2` searches the additions of two keys first
- With `-a` every addition found is printed, also with different numbers of keys
- Sequential keys and random keys in a small offsets span are searched with a BSGS interval search, the other cases use a meet in the middle search
- Added the `-F` parameter for the `-k` mode, it forces a number of keys whose search is over the safety limit of 4194304 table entries or combinations, those numbers of keys are skipped and reported as not searched when `-F` is not used
- The `Estimated RAM needed` and the `System RAM` are printed before the generation in every mode, not only in the `-k` mode
- In the normal mode the keys are written while they are generated, so the estimated RAM needed for them is 0 bytes

# Version 0.3.20260926
- In the `-k` mode the `Estimated RAM needed` for the requested `-n` keys and the `System RAM` are printed before the generation starts
- A warning is shown when the estimated RAM needed does not fit in the system RAM
- When the allocation of the table of generated publickeys fails, the memory needed is reported in the error message

# Version 0.2.20260922
- Added the `-k privatekey` parameter, it generates the `-n` private/publickey pairs of that privatekey (sequential or with random offsets using `-R`) and substracts every generated publickey from the `-p` publickey until one of the generated publickeys is reached, then the privatekey of the `-p` publickey is recovered and verified
- In the `-k` mode nothing is stored, no file is written and the generated keys are only printed to the stdout, with `-R` the offsets space is set with `-r A:B` or `-b bits`
- Added the `-a` parameter, with `-k` it looks for all the matches instead of stopping on the first one
- Fixed a 1 byte overflow when the output buffers are cleared

# Version 0.1.20210918
- Added outputs in modes address, rmd160
- Added compress or uncompress output for all modes, this is an address or hash rmd160 from a compress or uncompress publickey

# Version 0.1
- First Release
