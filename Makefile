CPP=g++
CPPFLAGS= -Wall -g -O0 -I./kirk
LDFLAGS= -L./kirk -lrt -lkirk
SOURCES=aes.cpp ec.cpp sha1.cpp ipltool.cpp
EXECUTABLE=ipltool

all:
	cd kirk && $(MAKE) && cd ..	
	$(CPP) $(CPPFLAGS) $(SOURCES) $(LDFLAGS) -o $(EXECUTABLE)
clean:
	cd kirk && $(MAKE) clean && cd ..
	rm -rf $(EXECUTABLE)