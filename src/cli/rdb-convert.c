/* TBD */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>

void printUsage() {
    printf("Usage: ./rdb-convert [-i FILE] [-c CONVERT] <[-o OUTPUT]>\n");
    printf("Options:\n");
    printf("\t-i|--input FILE           Input {FILE}\n");
    printf("\t-c|--convert CONVERT      Convert to {'json', 'resp'}\n");
    printf("\t-o|--output OUTPUT        Output to {'stdout', FILE, IP:PORT, :PORT}\n");
    printf("\t-h, --help                Display this help message\n");
}

int main(int argc, char **argv)
{

    int option;
    int option_index = 0;
    char *input_file = NULL;
    char *convert_option = NULL;
    char *output_option = NULL;

    struct option long_options[] = {
            {"input",  no_argument,        0, 'i'},
            {"convert",  required_argument,  0, 'c'},
            {"output", optional_argument,  0, 'o'},
            {"help",   no_argument,        0, 'h'},
            {0, 0, 0, 0}
    };


    while ((option = getopt_long(argc, argv, "i:c:o::h", long_options, &option_index)) != -1) {
        switch (option) {
            case 'i':
                input_file = optarg;
                break;
            case 'c':
                convert_option = optarg;
                break;
            case 'o':
                output_option = optarg;
                break;
            case 'h':
                printUsage();
                return 0;
            case '?':
                printf("Invalid option\n");
                printUsage();
                return 1;

            default:
                break;
        }
    }

    printf("Input file: %s\n", input_file != NULL ? input_file : "Not specified");
    printf("Convert option: %s\n", convert_option != NULL ? convert_option : "Not specified");
    printf("Output option: %s\n", output_option != NULL ? output_option : "Not specified");

    return 0;
}
