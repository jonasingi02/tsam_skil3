# Compiler
CXX = g++

# Target executable
TARGET = puzzlesolver

# Source file
SRC = puzzlesolver.cpp

# Default target to build the executable
all:
	$(CXX) $(SRC) -o $(TARGET)

# Clean rule to remove the executable
clean:
	rm -f $(TARGET)

# Phony target to avoid conflicts with files named 'all' or 'clean'
.PHONY: all clean
