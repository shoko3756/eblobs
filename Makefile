.PHONY: all run clean

all:
	cmake -S . -B build
	cmake --build build

run: all
	./build/emailblob

clean:
	rm -rf build