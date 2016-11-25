all:
	gcc -Iinclude -O2 -g src/*.c -o pe
win:
	i686-w64-mingw32-gcc -Iinclude -O2 -g src/*.c -o pe.exe
clean:
	rm -f pe pe.exe
