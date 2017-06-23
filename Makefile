CPP=gcc
CPPFLAGS= -Wall -g -O0
LDFLAGS=
SOURCES=amctrl.c aes.c bn.c crypto.c ec.c ec_ipltool.c kirk_engine.c ipltool.c sha1.c utils.c
EXECUTABLE=ipltool

all:
	$(CPP) $(CPPFLAGS) $(SOURCES) $(LDFLAGS) -o $(EXECUTABLE)
clean:
	rm -rf $(EXECUTABLE)