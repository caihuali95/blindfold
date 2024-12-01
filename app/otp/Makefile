.PHONY: clean

all: otp

otp:
	$(CC) otp.c hmac-sha1.c sha1.c -o $(OUT)/otp

clean:
	rm $(OUT)/otp
