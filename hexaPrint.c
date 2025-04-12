#include <stdio.h>

void PrintHex(unsigned char buffer[], size_t length) { 
    for (size_t i = 0; i < length; i++) {
        printf("%02X ", buffer[i]);  // Print each byte as a 2-digit hex
    }
}

int main(int argc, char **args) {
    if(argc < 2) {
        perror("Filename argument needed");
        return 1;
    }
    FILE *file = fopen(args[1], "rb");
    if (file == NULL) {
        perror("Error opening file");
        return 1;
    }
    unsigned char buffer[128];
    size_t bytesRead;
    while ((bytesRead = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        PrintHex(buffer, bytesRead);
    }

    fclose(file);  // Close the file after reading
    return 0;
}