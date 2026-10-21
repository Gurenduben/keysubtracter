# keysubtracter
Bitcoin and Altcoins Publickey subtracter

Generate multiple but different "copies" of a publickey, Actually Added and substracted publickeys.

Post: https://bitcointalk.org/index.php?topic=5360656.0

Download, clone this repository:

`git clone https://github.com/gurenduben/keysubtracter.git`

Compile:

`make`

## Make copies of any publickey

This copies are generated at different offset of the orginal publickey.

For example to make 100 copies of the puzzle 120 you need to execute the next command:

`./keysubtracter -p 02ceb6cbbcdbdf5ef7150682150f4ce2c6f4807b349827dcdbdd1f2efa885a2630 -n 100 -b 120`

this will create 100 subtracted publickeys, well this is 50 Added publickeys and 50 substracted publickeys

## How the generated publickeys will be distributed?

Almost the half of those publickey will land in the 120 bits space `-b 120` becuase the input publickey supposedly is located in bitspace 119-120

And the 50 Upper keys are distributed in the 120 bit space divided by 50 upper the Original publickey
And the 50 Lower keys are distributed in the 120 bit space divided by 50 lower the original publickey

## How i can generated publickeys separated by a specific difference ?

Well to avoid add extra modifications to the code for now this need to be calculated with the current parameters.

if you want to generate 10 publickeys separated each with 10 of difference you need to specify a range of 100 divided by 2 with `-r 0:32` 32 hexadecimal is 50 decimal

`./keysubtracter -p 02ceb6cbbcdbdf5ef7150682150f4ce2c6f4807b349827dcdbdd1f2efa885a2630 -n 10 -r 0:32`

Example output:

```
023e40191ed19ba1c82d3948ffad7d11efc7352e8a071b09750fc0a62cba295f15 # - 10
02ad82cfd538d8f9a98ea7d2393a958962d3dd783456284353084ad74e459ca98c # + 10
029649575661e11d5c7c277d008c7a6d6a56c14824e31673a5a49809f94777858e # - 20
02a1c7e1fffa740388689234491047208e0f7c23a9bee61b61ef035a6d016a709c # + 20
02a3c299147e9cb77fc03b13712700361b6175e3fa3521a297854c73f680f8b389 # - 30
028a6ee5e557bf738107e02cf5533dd40d6390f4a4a1539092774246c1352583b8 # + 30
03911f949fe7d1c81152974161306cda43c810ec50839cee0ff1fd047b25eb95bf # - 40
0311d6b86415d2122e4103d63906cfda90f9f6359f2b90887839b25a2fe7e6de6b # + 40
02c234090ac778e0e311d4306a9ba41e042900f44f7166e3a17786e4376bfdfabf # - 50
039f147c6939d4d3b66eb7ae37f67652d1b4e28794a55ca39e22db6eb2c8949505 # + 50
02ceb6cbbcdbdf5ef7150682150f4ce2c6f4807b349827dcdbdd1f2efa885a2630 # target
```

Not clear how to calculate the range this is the formula

`(number keys that you want * expected difference )  bewteen two`

## How i can use those copies ?

You can use it in any program that accept multiple publickeys for cracking, kangaroo, BSGS of JPL or in my keyhunt with modes `bsgs` or `xpoint`

## Can i generated publickeys at random offset

Yes with `-R` but is a slow method because it use Scalar multiplication instead Point Addition

## Generate publickeys from a privatekey and substract them from a publickey

With the parameter `-k privatekey` the program generates the `-n` private/publickey
pairs of that privatekey and checks if the publickey given with `-p` is the
**addition of 10 or more of the generated publickeys**.  Every generated publickey
can be used only once in that addition.  When a match is found the privatekey of
the `-p` publickey is the addition of the generated privatekeys that produced it
and it is printed verified.

The minimum number of generated publickeys that must be added is set with
`-m number`, it is 10 by default.  With `-m 2` the additions of two generated
publickeys are searched first, as in the previous versions.

The keys are generated:

- sequentially `privatekey, privatekey+1, privatekey+2, ... privatekey+n-1`
- with a random offset `privatekey + random offset` when the parameter `-R` is used, the random offsets space is `0:4n` by default and it can be set with `-r A:B` or `-b bits` (those two parameters only affect the random generation)

**Nothing is stored**, no file is written (the `-o` parameter is ignored in this mode)
and the generated privatekeys and publickeys are only printed to the stdout while they
are generated, if you want to keep them just redirect the stdout to a file.
All the requested `-n` keys are generated before the search, because a match can
use any of them, also the last ones.  The search then stops as soon as a match is
found, use the parameter `-a` to print all the matches instead of the first one.

Example, 20 sequential keys from the privatekey `1`, the privatekeys `1` to `10`
add up to the privatekey `55` so the publickey of the privatekey `55` is the
addition of the first 10 generated publickeys:

`./keysubtracter -k 1 -p 02caf754272dc84563b0352b7a14311af55d245315ace27c65369e15f7151d41d1 -n 20`

```
0000000000000000000000000000000000000000000000000000000000000001 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798 # 1
0000000000000000000000000000000000000000000000000000000000000002 02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5 # 2
0000000000000000000000000000000000000000000000000000000000000003 02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9 # 3
0000000000000000000000000000000000000000000000000000000000000004 02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13 # 4
0000000000000000000000000000000000000000000000000000000000000005 022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4 # 5
...
[+] Match: target publickey is the addition of 10 generated publickeys: #1, #2, #3, #4, #5, #6, #7, #8, #9, #10
[+]   generated privatekey #1: 0000000000000000000000000000000000000000000000000000000000000001
...
[+]   generated privatekey #10: 000000000000000000000000000000000000000000000000000000000000000a
[+] Privatekey of the target publickey: 0000000000000000000000000000000000000000000000000000000000000037 verified
```

The old addition of two generated publickeys is still available with `-m 2`:

`./keysubtracter -k 1 -p 03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe -n 20 -m 2`

```
...
[+] Match: target publickey is the addition of 2 generated publickeys: #1, #8
[+]   generated privatekey #1: 0000000000000000000000000000000000000000000000000000000000000001
[+]   generated privatekey #8: 0000000000000000000000000000000000000000000000000000000000000008
[+] Privatekey of the target publickey: 0000000000000000000000000000000000000000000000000000000000000009 verified
```

The lines with the `[+]` prefix are the search information and they are printed to the
stderr, the keys are printed to the stdout, the comments with the number of every key
can be removed with `-x`.

Example with random offsets and `-m 2`, `-r 1:21` is the offsets space 1 to 32 in
hexadecimal and because the 32 requested keys are all the possible offsets they are
all generated but in a random order, here a pair of the generated privatekeys, for
example `6` plus `7`, adds up to the privatekey `13`:

`./keysubtracter -k 1 -n 32 -R -r 1:21 -p 03f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8 -m 2`

```
000000000000000000000000000000000000000000000000000000000000000a 03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7 # 1
000000000000000000000000000000000000000000000000000000000000001c 0255eb67d7b7238a70a7fa6f64d5dc3c826b31536da6eb344dc39a66f904f97968 # 2
0000000000000000000000000000000000000000000000000000000000000016 03421f5fc9a21065445c96fdb91c0c1e2f2431741c72713b4b99ddcb316f31e9fc # 3
...
0000000000000000000000000000000000000000000000000000000000000006 03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556 # 11
0000000000000000000000000000000000000000000000000000000000000007 025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc # 21
[+] Match: target publickey is the addition of 2 generated publickeys: #11, #21
[+]   generated privatekey #11: 0000000000000000000000000000000000000000000000000000000000000006
[+]   generated privatekey #21: 0000000000000000000000000000000000000000000000000000000000000007
[+] Privatekey of the target publickey: 000000000000000000000000000000000000000000000000000000000000000d verified
```

Which pair is reported depends on the generated keys, any pair of generated
privatekeys that adds up to the target privatekey is a valid match.

Because a privatekey can be the addition of different sets of the generated
privatekeys, the parameter `-a` prints every match, also with different numbers
of keys.  For example the publickey of the privatekey `21` is the addition of
sets of 2 to 6 of the first 20 keys of the privatekey `1`, 75 matches in total:

`./keysubtracter -k 1 -p 02352bbf4a4cdd12564f93fa332ce333301d9ad40271f8107181340aef25be59d5 -n 20 -m 2 -a`

### How the additions of 10 or more keys are searched

Every number of keys from `-m` to `-n` is tried in increasing order and every
generated key can be used only once.  Three searches are used:

- With sequential keys the addition of `count` keys is
  `(count * base privatekey + s)` times the generator point, where `s` is a sum
  of `count` distinct offsets and every value of `s` in a known interval is
  possible, so a baby-step giant-step (BSGS) search in that interval finds the
  only possible `s` for every `count`.  This is fast also for a big `-n`, it
  only gets slow when no match with a small number of keys exists and every
  number of keys up to `-n` must be tried.
- With random keys whose offsets are in a small enough span the same idea is
  used with the normalised offsets: a BSGS search finds the only offset sum
  that can make the target and a subset-sum reconstruction then finds the
  generated keys with that sum.
- In the other cases a meet-in-the-middle search stores the additions of half
  of the keys of every set and looks up the target minus the additions of the
  other half.

Finding a subset of at least 10 keys that adds up to a given publickey is a
subset-sum problem, for a general set of keys there is no exact search that is
fast for every `-n`.  When one number of keys would need a table or a number
of combinations over the safety limit of 4194304 entries, or over the system
RAM, that number of keys is skipped and reported as not searched instead of
wrongly reporting that there is no match.  The parameter `-F` forces those
searches, but they can need a very big amount of RAM and time.  With `-a` the
number of matches can also be very big.

How much memory is used? In the `-k` mode a table indexed by the x coordinate
of the publickey is used while the keys are generated to avoid repeated random
keys, every slot of that table uses 152 bytes and the table is at least the
double of the requested `-n` keys, and every generated privatekey, offset and
publickey is kept in memory for the search.  The search itself can need more
memory for its BSGS or meet-in-the-middle tables, a warning is printed when a
search table does not fit in the system RAM.  Nothing is written to the disk.

In the other modes (`-p` with `-b` or `-r`) the keys are written while they are generated and
none of them is kept in memory, so the estimated RAM needed for the keys is 0 bytes.

Before the generation starts, in every mode, the `Estimated RAM needed` is printed together
with the `System RAM` of the machine, a warning is shown when the estimated RAM needed does
not fit in the system RAM and, in the `-k` mode, the memory needed is reported again when the
allocation fails:

```
[+] Estimated RAM needed: 155.75 KB (159488 bytes), 152 bytes per slot for 1024 slots plus the 20 generated keys kept in memory
[+] System RAM: 3.85 GB (4131278848 bytes)
```

## Generate hashes rmd160 of the publickey
With the parameter `-f rmd160` you can select the format of the output

```./keysubtracter -p 02ceb6cbbcdbdf5ef7150682150f4ce2c6f4807b349827dcdbdd1f2efa885a2630 -n 10 -r 0:32 -f rmd160
682c50abbc29474dba1f5a5b49e8a2cdc8ec9515 # - 10
6aca33ba1636394c01606fb15ed4e3ca90d62267 # + 10
4c8a3be7643ac4fa10380f74fa32e02ec9751a4e # - 20
e5a8c3aade6998a2890ade3bdba058eaf3f76c3e # + 20
03f9243592bf038dc4bbbb5a1f7f91dbc52f4971 # - 30
44e75c4a6fcece151aa47ebf6a1381c959ecc337 # + 30
4edcf7c0078162514b645acd7073dcc63735f12e # - 40
22510f1ed8898ebb0f084ceda94b3c284ddbe05a # + 40
eabea28b06974094a9b5be9bc89d3b53c346a13e # - 50
ca051a1de4828bfab450b5f4570869187dc05138 # + 50
4b46e10a541aeec6be3fac709c256fb7da69308e # target
```

## Generate address of the publickey
With the parameter `-f address` you can select the format of the output
```./keysubtracter -p 02ceb6cbbcdbdf5ef7150682150f4ce2c6f4807b349827dcdbdd1f2efa885a2630 -n 10 -r 0:32 -f address
1AVpN26dFDuMS2YwseUMaJ794XjMxb14ry # - 10
1AjerabryCRsi8PQmyeqVmwqn5jMVGrf1j # + 10
17yhxFFoMHRqCpk2qwmCYU4shZFz7Pq9Bd # - 20
1MwKut3gKEqTctLL8SL1M5gPG5PsW3ntat # + 20
1N1VE8aLcq9TiBQZVetFVT2F9nrnWVxQu # - 30
17HL7FmQ61r5ieDhbDh6WEKZBKcohmux9U # + 30
18BzR5E6vsweQpwJcJb9ov2c2BWTxZ11Yd # - 40
148T5c5SLwDK4uGKhGHRy3x4y7wBQrYmRC # + 40
1NQDVSGomQk3hWhc5yVrXjpPJTDX83bqCb # - 50
1KRBcFAXzd3ij9BxjyM5gFreDZc2tpcNw8 # + 50
17s2b9ksz5y7abUm92cHwG8jEPCzK3dLnT # target
```

## Removing the comment information
Just add the parameter `-x` to hide the comment from the output. For non random substraction this will be ok, but for Random substractions you need to keep that information of the offset because if you hit some privatekey you need that information to get the targer privatekey back.

```
./keysubtracter -p 02ceb6cbbcdbdf5ef7150682150f4ce2c6f4807b349827dcdbdd1f2efa885a2630 -n 10 -r 0:32 -f address -x
1AVpN26dFDuMS2YwseUMaJ794XjMxb14ry
1AjerabryCRsi8PQmyeqVmwqn5jMVGrf1j
17yhxFFoMHRqCpk2qwmCYU4shZFz7Pq9Bd
1MwKut3gKEqTctLL8SL1M5gPG5PsW3ntat
1N1VE8aLcq9TiBQZVetFVT2F9nrnWVxQu
17HL7FmQ61r5ieDhbDh6WEKZBKcohmux9U
18BzR5E6vsweQpwJcJb9ov2c2BWTxZ11Yd
148T5c5SLwDK4uGKhGHRy3x4y7wBQrYmRC
1NQDVSGomQk3hWhc5yVrXjpPJTDX83bqCb
1KRBcFAXzd3ij9BxjyM5gFreDZc2tpcNw8
17s2b9ksz5y7abUm92cHwG8jEPCzK3dLnT
```

## Misc
In case of hit one privatekey the information that you need to calculate the target privatekey back is the next:
- original publickey target `-p publickey`
- range `-r A:B` or bit number `-b number`
- number of items requested `-n number`
- privatekey found
