/****************************
 *        Includes
 ****************************/
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 10000

/****************************
 *       Structs
 ****************************/

typedef struct virus {
  unsigned short SigSize;
  unsigned char *VirusName;
  unsigned char *Sig;
} Virus;

typedef struct link link;

typedef struct link {
  Virus *vir;
  link *nextVirus;
} link;

typedef struct {
  int offset;
  Virus *virus;
} Detection;

typedef enum { LITTLE = 0, BIG = 1 } Endian;

/****************************
 *          Globals
 ****************************/

link *lastNode = NULL;
link *globalVirusList = NULL;

/****************************
 *     Function Prototypes
 ****************************/

// Virus loading
Virus *readVirus(FILE *file, Endian endian);
link *parseVirusFile(FILE *file);

// Virus detection
void printVirus(Virus *virus, FILE *file);
void detect_virus(char *buffer, unsigned int size, link *virus_list);
Detection *scan_for_viruses(char *buffer, unsigned int size, link *virus_list,
                            int *numDetections);
// Virus removal
void neutralize_virus(char *fileName, int signatureOffset);

// Linked list
void list_print(link *virus_list, FILE *file);
void list_free(link *virus_list);
link *list_append(link *virus_list, Virus *data);

// Utilities
bool checkMagic(FILE *file, Endian *endian);
unsigned short parseSigLength(FILE *file, Endian endian);
unsigned char *parseStringFromFile(FILE *file, int count);
void PrintHex(FILE *file, unsigned char buffer[], size_t length);
void readLine(char *buffer, int size);
size_t readFromFile(char *filename, char *buffer);

// Menu functions
void loadSignatures();
void detectVirus();
void listPrint();
void neutralizeVirus();
void quit();

/****************************
 *     Menu Setup
 ****************************/

struct fun_desc {
  char *name;
  void (*fun)();
};

struct fun_desc menu[] = {{"Load signatures", loadSignatures},
                          {"Print signatures", listPrint},
                          {"Detect viruses", detectVirus},
                          {"Fix file", neutralizeVirus},
                          {"Quit", quit},
                          {NULL, NULL}};

int main(int argc, char **argv) {
  int menu_size = 0;
  while (menu[menu_size].name != NULL) {
    menu_size++;
  }
  char buf[12];
  while (1) {
    printf("\nselect operation from the following menu: \n");

    for (int i = 1; i < menu_size + 1; i++) {
      printf("%d. %s\n", i, menu[i - 1].name);
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

/**
 * Prompts the user for a virus signature file name,
 * parses the file, and stores the virus list in a global linked list.
 */
void loadSignatures() {
  printf("Please enter file signatures name:\n");
  char filename[100];
  readLine(filename, sizeof(filename));
  FILE *file = fopen(filename, "rb");
  if (file == NULL) {
    perror("Error opening file");
    return;
  }

  if (globalVirusList) {
    list_free(globalVirusList);
    lastNode = NULL;
  }
  globalVirusList = parseVirusFile(file);

  fclose(file);
}

/**
 * Prints a given buffer in hexadecimal format to the provided output file.
 * Each byte is printed as a two-digit hex number.
 */
void PrintHex(FILE *file, unsigned char buffer[], size_t length) {
  for (size_t i = 0; i < length; i++) {
    fprintf(file, "%02X ", buffer[i]);
  }
}

/**
 * Opens and parses a virus signature file.
 * Returns a linked list of virus signatures.
 */
link *parseVirusFile(FILE *file) {
  Endian endian;
  if (!checkMagic(file, &endian)) {
    fprintf(stderr, "File magic is not correct!\n");
    return NULL;
  }
  link *virusList = NULL;
  while (!feof(file)) {
    Virus *virus = readVirus(file, endian);
    if (virus != NULL) {
      virusList = list_append(virusList, virus);
    }
  }
  return virusList;
}

/**
 * Validates the magic number at the beginning of the file to determine
 * if it's a valid signature file. Also sets the endian format.
 * Returns true if the magic number is valid, false otherwise.
 */
bool checkMagic(FILE *file, Endian *endian) {
  unsigned char buffer[4];
  size_t bytesRead = fread(buffer, 1, 4, file);
  if (bytesRead != 4 || buffer[0] != 'V' || buffer[1] != 'I' ||
      buffer[2] != 'R' || (buffer[3] != 'L' && buffer[3] != 'B'))
    return false;
  *endian = (buffer[3] == 'L') ? LITTLE : BIG;
  return true;
}

/**
 * Reads a virus from the binary file, including size, name, and signature.
 * Returns a pointer to a Virus struct.
 */
Virus *readVirus(FILE *file, Endian endian) {
  Virus *virus = (Virus *)malloc(sizeof(Virus));
  if (!virus) {
    perror("Memory allocation failed\n");
    return NULL;
  }
  virus->SigSize = parseSigLength(file, endian);
  if (virus->SigSize == 0) {
    free(virus);
    return NULL;
  }
  virus->VirusName = parseStringFromFile(file, 16);
  virus->Sig = parseStringFromFile(file, (int)virus->SigSize);
  return virus;
}

/**
 * Reads and parses a 2-byte virus signature length from the file.
 * Adjusts for endian-ness based on the provided format.
 * Returns the parsed signature length or 0 if reading fails.
 */
unsigned short parseSigLength(FILE *file, Endian endian) {
  unsigned short sigLength = 0;
  if (endian == LITTLE) {
    // Checks for not reading empty data
    if (fread(&sigLength, 2, 1, file) != 1) { // Little-endian: LSB first
      return 0;
    }
  } else {
    unsigned char bytes[2];
    if (fread(bytes, 1, 2, file) != 2) { // Big-endian: MSB first
      return 0;
    }
    sigLength = (bytes[0] << 8) | bytes[1];
  }
  return sigLength;
}

/**
 * Reads a given number of bytes from a file and stores it in a
 * newly allocated buffer. Caller is responsible for freeing it.
 */
unsigned char *parseStringFromFile(FILE *file, int count) {
  unsigned char *string = (unsigned char *)calloc(count, sizeof(unsigned char));
  if (!string) {
    perror("Memory allocation failed\n");
    return NULL;
  }
  fread(string, 1, count, file);
  return string;
}

/**
 * Inserts in to the given virus_list and new virus
 * node named data. Returns pointer to the head of the newly
 * created list.
 */
link *list_append(link *virus_list, Virus *data) {
  link *newLink = (link *)malloc(sizeof(link));
  if (!newLink) {
    perror("Memory allocation failed\n");
    return NULL;
  }

  newLink->vir = data;
  newLink->nextVirus = NULL;

  if (virus_list == NULL) {
    virus_list = newLink;
    lastNode = newLink;
    return newLink;
  } else {
    lastNode->nextVirus = newLink;
    lastNode = newLink;
  }
  return virus_list;
}

/**
 * Wrapper for list_print using the global virus list.
 * Prints all loaded viruses to stdout.
 */
void listPrint() {
  if (globalVirusList == NULL)
    return;
  list_print(globalVirusList, stdout);
}

void list_print(link *virus_list, FILE *file) {
  link *current = virus_list;
  while (current != NULL && current->vir != NULL) {
    Virus *curr = current->vir;
    printVirus(curr, file);
    current = current->nextVirus;
  }
}

void printVirus(Virus *virus, FILE *file) {
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
  if (globalVirusList == NULL) {
    fprintf(stderr, "You need to provide signature virus file first\n");
    return;
  }
  char *buffer = calloc(BUFFER_SIZE, sizeof(char));
  if (!buffer) {
    perror("Memory allocation failed\n");
    return;
  }
  if (buffer) {
  }
  printf("Please enter file name to scan:\n");
  char filename[100];
  readLine(filename, sizeof(filename));
  size_t bytesRead = readFromFile(filename, buffer);
  if (bytesRead == 0) {
    fprintf(stderr, "Error reading from file");
    free(buffer);
    return;
  }

  detect_virus(buffer, (unsigned int)bytesRead, globalVirusList);
  free(buffer);
}

void detect_virus(char *buffer, unsigned int size, link *virus_list) {
  int count = 0;
  Detection *detections = scan_for_viruses(buffer, size, virus_list, &count);
  for (int i = 0; i < count; i++) {
    printf("Starting byte: %d\n", detections[i].offset);
    printf("Virus name: %s\n", detections[i].virus->VirusName);
    printf("Signature size: %hu\n", detections[i].virus->SigSize);
  }
  free(detections);
}

// Helper function: recieves buffer (file data), size to scan, virus_list &
// changes numDetections to number of Viruses found. returns Detections*, list
// of viruses with offsets detected in the buffer.
Detection *scan_for_viruses(char *buffer, unsigned int size, link *virus_list,
                            int *numDetections) {
  int capacity = 10;
  int count = 0;
  Detection *detections = (Detection *)malloc(capacity * sizeof(Detection));
  if (!detections) {
    perror("Memory allocation failed\n");
    return NULL;
  }

  link *tmp_virus_list;
  for (int i = 0; i < size; i++) {
    tmp_virus_list = virus_list;
    while (tmp_virus_list != NULL) {
      Virus *virus = tmp_virus_list->vir;
      if (virus != NULL &&
          memcmp(&buffer[i], virus->Sig, virus->SigSize) == 0) {
        // Scalable capacity
        if (count >= capacity) {
          capacity *= 2;
          detections = realloc(detections, capacity * sizeof(Detection));
          if (!detections) {
            perror("Memory allocation failed\n");
            return NULL;
          }
        }
        detections[count].virus = virus;
        detections[count].offset = i;
        count++;
      }
      tmp_virus_list = tmp_virus_list->nextVirus;
    }
  }
  *numDetections = count;
  return detections;
}

// Helper function: Reads file content to buffer, returns bytes read from file
size_t readFromFile(char *filename, char *buffer) {
  FILE *file = fopen(filename, "rb");
  if (file == NULL) {
    perror("Error opening file");
    return 0;
  }

  size_t bytesRead = fread(buffer, 1, BUFFER_SIZE, file);
  fclose(file);
  return bytesRead;
}

/**
 * Prompts the user for a filename, scans it for viruses,
 * and neutralizes them in-place by replacing the first byte
 * of each virus with a RET (0xC3) instruction.
 */
void neutralizeVirus() {
  if (globalVirusList == NULL) {
    fprintf(stderr, "You need to provide signature virus file first\n");
    return;
  }

  char *buffer = calloc(BUFFER_SIZE, sizeof(char));
  if (!buffer) {
    perror("Memory allocation failed\n");
    return;
  }
  printf("Please enter file name to fix:\n");
  char filename[100];
  readLine(filename, sizeof(filename));
  size_t bytesRead = readFromFile(filename, buffer);
  if (bytesRead == 0) {
    fprintf(stderr, "Error reading from file");
    free(buffer);
    return;
  }

  int count = 0;
  Detection *detections =
      scan_for_viruses(buffer, bytesRead, globalVirusList, &count);
  for (int i = 0; i < count; i++) {
    neutralize_virus(filename, detections[i].offset);
  }
  free(detections);
  free(buffer);
}

/**
 * Overwrites a specific byte in the file with a RET (0xC3) instruction,
 * effectively neutralizing the virus starting at the given offset.
 */
void neutralize_virus(char *fileName, int signatureOffset) {
  FILE *file = fopen(fileName, "r+b");
  if (file == NULL) {
    perror("Error opening file for neutralization");
    return;
  }

  fseek(file, signatureOffset, SEEK_SET);

  unsigned char retOpCode = 0xC3;
  fwrite(&retOpCode, 1, 1, file);

  fclose(file);
}

/**
 * Reads a line of input from stdin into the buffer,
 * and removes the newline character if present.
 */
void readLine(char *buffer, int size) {
  fgets(buffer, size, stdin);
  buffer[strcspn(buffer, "\n")] = '\0';
}

/**
 * Frees the global virus list if allocated and exits the program.
 */
void quit() {
  if (globalVirusList != NULL)
    list_free(globalVirusList);
  exit(0);
}