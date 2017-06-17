CC=g++
CFLAGS=-Wall
LDFLAGS=
SOURCES=aes.cpp ec.cpp sha1.cpp ipltool.cpp
EXECUTABLE=ipltool
all:
	$(CC) $(CFLAGS) $(SOURCES) $(LDFLAGS) -o $(EXECUTABLE)
clean:
	rm -rf $(EXECUTABLE)