#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include "ebpfcni.h"

struct ip_pair {
    __u32 saddr;
    __u32 daddr;
};

int main(int argc, char* argv[]) {
    // Specify the path to the BPF map file, which is typically under /sys/fs/bpf/
    const char *obj_file = "./ebpfcni.bpf.o";

    // Load the BPF map from the specified file
    struct bpf_object *obj;
    struct bpf_map *map;

    obj = bpf_object__open_file(obj_file, NULL);
    if (!obj) {
        fprintf(stderr, "Error opening BPF object file\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Error loading BPF object file\n");
        bpf_object__close(obj);
        return 1;
    }

    map = bpf_object__find_map_by_name(obj, "iprules");
    if (!map) {
        fprintf(stderr, "Error finding BPF map by name\n");
        bpf_object__close(obj);
        return 1;
    }

    // Define the key and value for the update
    struct ip_pair key;

    key.saddr =  ipv4_to_u32(argv[1]);  // Convert the source address to network byte order
    key.daddr = ipv4_to_u32(argv[2]);  // Convert the destination address to network byte order
    int value = atoi(argv[3]);

    // Update the BPF map element
    int ret = bpf_map__update_elem(map, &key, sizeof(struct ip_pair), &value, sizeof(int) ,  BPF_ANY);
    if (ret) {
        fprintf(stderr, "Error updating BPF map element: %s\n", strerror(-ret));
        bpf_object__close(obj);
        return 1;
    }

    // Clean up and close the BPF map and object
    bpf_object__close(obj);

    return 0;
}
