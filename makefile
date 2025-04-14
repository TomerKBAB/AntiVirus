all: AntiVirus

AntiVirus: AntiVirus.c
	gcc -Wall -m32 -g -Wall -o AntiVirus AntiVirus.c

clean:
	rm -f AntiVirus
