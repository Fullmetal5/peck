all:
	g++ -O2 -g pe.cpp -o pe
win:
	i686-w64-mingw32-g++ -O2 -g pe.cpp -o pe.exe
clean:
	rm -f pe pe.exe
