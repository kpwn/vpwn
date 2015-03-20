all:
	gcc *.m -o vpwn -framework IOKit -framework Foundation -m64
	gcc patch.c lsym.m -o patch -framework Foundation -framework IOKit
	gcc unpatch.c lsym.m -o unpatch -framework Foundation -framework IOKit
