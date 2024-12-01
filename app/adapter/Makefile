.PHONY: clean

all: adapter

adapter:
	$(CXX) adapter.cpp hmac-sha256.c sha256.c aesv8-armx64.S -o $(OUT)/adapter

clean:
	rm $(OUT)/adapter
