#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Function to convert an IPv4 string to a u32 integer
uint32_t ipv4_to_u32(const char *ipv4_str) {
    uint32_t result = 0;
    char *token, *str, *saveptr;
    int i = 0;
    
    // Copy the input string to a temporary buffer
    str = strdup(ipv4_str);
    
    // Tokenize the string using '.' as the delimiter
    token = strtok_r(str, ".", &saveptr);
    
    while (token != NULL) {
        result = result << 8; // Shift the previous result left by 8 bits
        result |= atoi(token); // Add the current octet to the result
        token = strtok_r(NULL, ".", &saveptr);
        i++;
    }
    
    // Free the temporary buffer
    free(str);
    
    // Check if we successfully parsed all 4 octets
    if (i != 4) {
        printf("Invalid IPv4 format: %s\n", ipv4_str);
        exit(1);
    }
    
    return result;
}