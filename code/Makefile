FLAGS=-std=c++20 -Wall -Wextra -pedantic -Wconversion -lpthread -O3

all: sha256.o gen-passwd.o check-passwd.o
	g++ -o gen-passwd ${FLAGS} random.hpp gen-passwd.o sha256.o passwd-utils.hpp
	g++ -o check-passwd ${FLAGS} random.hpp check-passwd.o sha256.o passwd-utils.hpp

%.o: %.cpp
	g++ ${FLAGS} -c -o $@ $<

clean:
	rm -rf *.o *.gch check-passwd gen-passwd

rainbow: RainbowTable.cpp
	g++ -o rainbow RainbowTable.cpp sha256.cpp main.cpp ${FLAGS}