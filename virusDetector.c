/****************************
 *        Includes
 ****************************/
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#define BUFFER_SIZE 10000

/****************************
 *       Structs 
 ****************************/

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

/****************************
 *          Globals 
 ****************************/

link *lastNode = NULL;  
link* globalVirusList = NULL;

/****************************
 *     Function Prototypes
 ****************************/

 // Virus loading
Virus* readVirus(FILE* file, Endian endian);
link* parseVirusFile(FILE *file);

// Virus detection
void printVirus(Virus* virus, FILE* file);
void detect_virus(char *buffer, unsigned int size, link *virus_list);

// Linked list
void list_print(link *virus_list, FILE *file);
void list_free(link *virus_list);
link* list_append(link* virus_list, Virus* data);


// Utilities
bool checkMagic(FILE *file, Endian *endian);
unsigned short parseSigLength(FILE *file, Endian endian);
unsigned char* parseStringFromFile(FILE *file, int count);
void PrintHex(FILE *file, unsigned char buffer[], size_t length);
void readLine(char* buffer, int size);

// Menu functions
void loadSignatures();
void detectVirus();
void listPrint();
void quit();

/****************************
 *     Menu Setup
 ****************************/

struct fun_desc{
  char *name;
  void (*fun)();
};

struct fun_desc menu[] = {
  {"Load signatures", loadSignatures},
  {"Print signatures", listPrint},
  {"Detect viruses", detectVirus},
//   {"Fix file", fixFile},
  {"Quit", quit},
  {NULL, NULL}
};

int main(int argc, char **argv) {
    int menu_size = 0;
    while (menu[menu_size].name != NULL) {
        menu_size++;
    }
    char buf[12];
    while (1) {
        printf("\nselect operation from the following menu: \n");

        for (int i = 1; i < menu_size + 1; i++) {
            printf("%d. %s\n",i ,menu[i - 1].name);
        }

        if (fgets(buf, 12, stdin) == NULL) {
            printf("recieved EOF, exists\n");
            quit();
        }
        int pos = atoi(buf);
        if ((pos <= 0) || (pos > menu_size)) {
            printf("not within bounds, exists\n");
            quit();
        }
        menu[pos - 1].fun();
    }
}

void loadSignatures() {
    printf("Please enter file signatures name:\n");
    char filename[100];
    readLine(filename, sizeof(filename));
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        perror("Error opening file");
        return;
    }

    globalVirusList =  parseVirusFile(file);
}

void PrintHex(FILE *file, unsigned char buffer[], size_t length) { 
    for (size_t i = 0; i < length; i++) {
        fprintf(file, "%02X ", buffer[i]);  
    }
}

/**
 * Opens and parses a virus signature file.
 * Returns a linked list of virus signatures.
 */
link* parseVirusFile(FILE *file) {
    Endian endian;
    if (!checkMagic(file, &endian)) {
        fprintf(stderr, "File magic is not correct!\n");
        return NULL;
    }
    link *virusList = NULL;
    while (!feof(file)) {
        Virus* virus = readVirus(file, endian);
        if(virus != NULL) {
            virusList = list_append(virusList, virus);
        }
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

/**
 * Reads a virus from the binary file, including size, name, and signature.
 * Returns a pointer to a Virus struct.
 */
Virus* readVirus(FILE* file, Endian endian) {
    Virus* virus = (Virus *) malloc(sizeof(Virus));
    virus->SigSize = parseSigLength(file, endian);
    if(virus->SigSize == 0) {
        free(virus);
        return NULL;
    }
    virus->VirusName = parseStringFromFile(file, 16);
    virus->Sig = parseStringFromFile(file, (int)virus->SigSize);
    return virus;
}

unsigned short parseSigLength(FILE *file, Endian endian) {
    unsigned short sigLength = 0;
    if (endian == LITTLE) {
        // Checks for not reading empty data
        if (fread(&sigLength, 2, 1, file) != 1) { // Little-endian: LSB first
            return 0;
        }
    }
    else {
        unsigned char bytes[2];
        if (fread(bytes, 1, 2, file) != 2) { // Big-endian: MSB first
            return 0;
        }
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

void listPrint() {
    if (globalVirusList == NULL)
        return;
    list_print(globalVirusList, stdout);
}

void list_print(link *virus_list, FILE *file) {
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

/**
 * Scans a memory buffer for known virus signatures.
 * If found, prints their starting location and metadata.
 */
void detectVirus() {
    if(globalVirusList == NULL) {
        fprintf(stderr, "You need to provide signature virus file first\n");
        return;
    }
    printf("Please enter file name to scan:\n");
    char filename[100];
    readLine(filename, sizeof(filename));

    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        perror("Error opening file");
        return;
    }

    char* buffer = malloc(BUFFER_SIZE);

    size_t bytesRead = fread(buffer, 1, BUFFER_SIZE, file);
    fclose(file);

    detect_virus(buffer, (unsigned int) bytesRead, globalVirusList);

    free(buffer);
}

void detect_virus(char *buffer, unsigned int size, link *virus_list) {
    link* tmp_virus_list = virus_list;
    for (int i = 0; i < size; i++) {
        tmp_virus_list = virus_list;
        while (tmp_virus_list != NULL) {
            Virus* virus = tmp_virus_list->vir;
            if (virus != NULL && memcmp(&buffer[i], virus->Sig, virus->SigSize) == 0) {
                printf("Starting byte: %d\n", i);
                printf("Virus name: %s\n", virus->VirusName);
                printf("Signature size: %hu\n", virus->SigSize);
            }
            tmp_virus_list = tmp_virus_list->nextVirus;
        } 
    }
}

void readLine(char* buffer, int size) {
    fgets(buffer, size, stdin);
    buffer[strcspn(buffer, "\n")] = '\0';
}

void quit() {
    if(globalVirusList != NULL)
        list_free(globalVirusList);
    exit(0);
}