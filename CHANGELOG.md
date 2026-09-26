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
