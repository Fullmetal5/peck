all:
	gcc -O2 -g pe.c -o pe
win:
	i686-w64-mingw32-gcc -O2 -g pe.c -o pe.exe
clean:
	rm -f pe pe.exe
