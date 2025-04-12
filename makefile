# Compiler
CC = gcc

# Compiler flags
CFLAGS = -g -Wall

# Source files
# SRC = hexaPrint.c virusDetector.c 
SRC = virusDetector.c 

# Object files
OBJ = $(SRC:.c=.o)

# Output file
OUTPUT = main # Replace with your desired output file name

# Targets
all: $(OUTPUT)

$(OUTPUT): $(OBJ)
	$(CC) $(OBJ) -o $(OUTPUT)

# Compile the source files to object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean the object files and output file
clean:
	rm -f $(OBJ) $(OUTPUT)

# Phony targets (not files)
.PHONY: all clean
