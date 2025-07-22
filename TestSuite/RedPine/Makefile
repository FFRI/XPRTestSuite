all: loader test scan_libs loader_big_sur in_memory_scan

scan_libs: scan_libs.m
	clang -O3 -arch x86_64 -mmacos-version-min=10.15 -framework Foundation $< -o $@

loader_big_sur: loader_big_sur.mm
	clang++ -O3 -arch x86_64 -mmacos-version-min=10.15 -std=c++14 -framework Foundation $< -o $@
	codesign -f -s - --option=runtime $@

loader: loader.mm
	clang++ -O3 -arch x86_64 -std=c++14 -framework Foundation $< -lsqlite3 -lmacho_dyld -o $@
	codesign -f -s - --option=runtime $@

test: test.c
	clang -O3 -arch x86_64 -mmacos-version-min=10.15 $< -o $@

in_memory_scan: in_memory_scan.c
	clang -O3 -arch x86_64 -mmacos-version-min=10.15 $< -o $@

run: loader test in_memory_scan
	./loader ./test &
	./in_memory_scan &

run_big_sur: loader_big_sur test
	./loader_big_sur ./test /System/Library/Frameworks/CoreLocation.framework/CoreLocation

clean:
	rm -f loader test scan_libs loader_big_sur in_memory_scan
