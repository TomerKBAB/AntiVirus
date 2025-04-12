#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

typedef struct virus {
    unsigned short SigSize;
    unsigned char* VirusName;
    unsigned char* Sig;
} Virus;

typedef struct link link;  

typedef struct link {
    Virus *vir;
    link *nextVirus;
} link;

typedef enum {
    LITTLE = 0,
    BIG = 1
} Endian;

link *lastNode = NULL;  

bool checkMagic(FILE *file, Endian *endian);
unsigned short parseSigLength(FILE *file, Endian endian);
unsigned char* parseStringFromFile(FILE *file, int count);
link* list_append(link* virus_list, Virus* data);
void PrintHex(FILE *file, unsigned char buffer[], size_t length);
void list_print(link *virus_list, FILE *file);
FILE* openFile(char *name);
link* parseVirusFile(FILE *file);
void list_free(link *virus_list);
void printVirus(Virus* virus, FILE* file);
Virus* readVirus(FILE* file, Endian endian);

int main(int argc, char **argv) {
    if (argc < 2) {
        perror("Virus input file required!");
        return 1;
    }
    FILE *file = openFile(argv[1]);

    link *virusList = parseVirusFile(file);

    list_print(virusList, stdout);

    list_free(virusList);
    
    fclose(file);

}

void PrintHex(FILE *file, unsigned char buffer[], size_t length) { 
    for (size_t i = 0; i < length; i++) {
        fprintf(file, "%02X ", buffer[i]);  
    }
}

FILE* openFile(char *name) {
    FILE *file = fopen(name, "rb");
    if (file == NULL) {
        perror("Error opening file");
        exit(1);
    }
    return file;
}

link* parseVirusFile(FILE *file) {
    Endian endian;
    if (!checkMagic(file, &endian)) {
        perror("File magic list_append is not correct");
        exit(1);
    }
    link *virusList = NULL;
    while (!feof(file)) {
        Virus* virus = readVirus(file, endian);
        virusList = list_append(virusList, virus);
    }
    return virusList;
}

bool checkMagic(FILE *file, Endian *endian) {
    unsigned char buffer[4];
    size_t bytesRead = fread(buffer, 1, 4, file);
    if (bytesRead != 4 || buffer[0] != 'V' || buffer[1] != 'I' || buffer[2] != 'R' || (buffer[3] != 'L' && buffer[3] != 'B'))
        return false;
    *endian = (buffer[3] == 'L') ? LITTLE : BIG;
    return true;
}

Virus* readVirus(FILE* file, Endian endian) {
    Virus* virus = (Virus *) malloc(sizeof(Virus));
    virus->SigSize = parseSigLength(file, endian);
    virus->VirusName = parseStringFromFile(file, 16);
    virus->Sig = parseStringFromFile(file, (int)virus->SigSize);
    return virus;
}

unsigned short parseSigLength(FILE *file, Endian endian) {
    unsigned short sigLength = 0;
    if (endian == LITTLE) {
        fread(&sigLength, 2, 1, file);  // Little-endian: LSB first
    } else {
        unsigned char bytes[2];
        fread(bytes, 1, 2, file);  // Big-endian: MSB first
        sigLength = (bytes[0] << 8) | bytes[1];
    }
    return sigLength;
}

unsigned char* parseStringFromFile(FILE *file, int count) {
    unsigned char* string = (unsigned char*) calloc(count, sizeof(unsigned char));
    fread(string, 1, count, file);
    return string;
}

link* list_append(link* virus_list, Virus* data) {
    link *newlink = (link *)malloc(sizeof(link));

    newlink->vir = data;
    newlink->nextVirus = NULL;

    if (virus_list == NULL) {
        virus_list = newlink;
        lastNode = newlink;
        return newlink;
    }
    else {
        lastNode->nextVirus = newlink;
        lastNode = newlink;
    }
    return virus_list;
}

void list_print(link *virus_list, FILE *file) {
    if (virus_list == NULL)
        return;
    link* current = virus_list;
    while (current != NULL && current->vir != NULL) {
        Virus *curr = current->vir;
        printVirus(curr, file);
        current = current->nextVirus;
    }
}

void printVirus(Virus* virus, FILE* file) {
    fprintf(file, "Virus name: %s\n", virus->VirusName);
    fprintf(file, "Virus size: %hu\n", virus->SigSize);
    fprintf(file, "signature:\n");
    PrintHex(file, virus->Sig, virus->SigSize);
    fprintf(file, "\n\n");
}

void list_free(link *virus_list) {
    while (virus_list != NULL) {
        link *temp = virus_list;
        virus_list = virus_list->nextVirus;
        
        // Free virus content
        free(temp->vir->VirusName);
        free(temp->vir->Sig);
        free(temp->vir);
        free(temp);
    }
}