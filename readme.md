## path to tool inside pin directory:
~/pin/source/tools/FalseSharingDetector/false_share_detector.cpp
sym link this with the repo

## using tool
to run tool against test code:
- `make pin`

## Programs testing against
- pbzip2
- xz


When testing these linux compression tools, run them against data in the TestingData folder. 
Randomly generate using this command:
`dd if=/dev/urandom of=TestingData/testfile.bin bs=1M count=200`