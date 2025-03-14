# Complier and Linker
CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -g
LDFLAGS = -lssl -lcrypto

# Directories
SRC_DIR = src # houses the source code files for an application (libiray), separating them from other project assets
OBJ_DIR = obj # sets the directory where object and other intermediate files should be placed when building a project
BIN_DIR = bin # subdirectory of the root directory in Unix-like operating systems that contains the executable programs
SSL_DIR = ssl_certs # where Puppet stores its cerificate infrastructure, including private and public keys, certificates, and CRL

# Targets
TARGETS = $(BIN_DIR)/server $(BIN_DIR)/client

# Source and Object Files
SOURCES = $(SRC_DIR)/server.c $(SRC_DIR)/client.c
OBJECTS = $(SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

# Default Target
all: check_dependencies generate_ssl_certs $(TARGETS)

# CHeck and Install Dependencies if NEcessary
check_dependencies:
	@which apt-get > /dev/null && { \
	    echo "Updating package lists..."; \
		sudo apt-get update; \
		echo "Installing build-essential and libssl-dev..."; \
		sudo apt-get install -y build-essential libssl-dev; \
	} || { \
		echo "apt-get not found. Please install build-essential and libssl-dev manually."; \
	}


# Generate SSL Certificates 
generate_ssl_certs: | $(SSL_DIR)
	@echo "Generating SSl certificates..."
	openssl genpkey -algorithm RSA -out $(SSL_DIR)/server.key
	openssl req -new -key $(SSL_DIR)/server.key -out $(SSL_DIR)/server.csr -subj "/C=US/ST=State/L=CIty/O=Organization/CN=localhost"
	openssl x509 -req -in $(SSL_DIR)/server.csr - signkey $(SSL_DIR)/server.eky -out $(SSL_DIR)/server.crt 

# Ensure that obj, bin, and ssl_certs directories exist
$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(BIN_DIR):
	mkdir -p $(SSL_DIR)

$(SSL_DIR):
	mkdir -p $(SSL_DIR)

# Build Server
$(BIN_DIR)/server: $(OBJ_DIR)/server.o | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(OBJ_DIR)

# Build Client
$(BIN_DIR)/client: $(OBJ_DIR)/client.o
	$(CC) $(CFLAGS) -c -o $@ $<

# Compile Source Files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

# Clean Up
clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR) $(SSL_DIR)

.PHONY: all clean check_dependcies generate_ssl_certs