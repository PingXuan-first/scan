#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BUFFER 1024

void display_binary(unsigned char *buffer, int size, int format);
void perform_operation(unsigned char *buffer, int size, int operation);
void print_menu();

int main() {
    FILE *file;
    char filename[256];
    unsigned char buffer[MAX_BUFFER];
    size_t bytesRead;

    printf("请输入二进制文件名(示例:test.bin): ");
    scanf("%255s", filename);

    file = fopen(filename, "rb");
    if (file == NULL) {
        printf("无法打开文件 %s\n", filename);
        return 1;
    }

    bytesRead = fread(buffer, 1, MAX_BUFFER, file);
    printf("已读取 %zu 字节\n", bytesRead);

    while (1) {
        print_menu();
        int choice;
        scanf("%d", &choice);

        switch (choice) {
            case 1:
                printf("\n二进制格式:\n");
                display_binary(buffer, bytesRead, 2);
                break;
            case 2:
                printf("\n十六进制格式:\n");
                display_binary(buffer, bytesRead, 16);
                break;
            case 3:
                printf("\n八进制格式:\n");
                display_binary(buffer, bytesRead, 8);
                break;
            case 4:
                {
                    int op;
                    printf("选择操作 (1:与, 2:或, 3:非): ");
                    scanf("%d", &op);
                    perform_operation(buffer, bytesRead, op);
                }
                break;
            case 5:
                fclose(file);
                return 0;
            default:
                printf("无效选择\n");
        }

        printf("\n按回车继续...");
        getchar();
        getchar();
    }
}

void display_binary(unsigned char *buffer, int size, int format) {
    for (int i = 0; i < size; i++) {
        if (format == 2) {
            for (int j = 7; j >= 0; j--) {
                printf("%d", (buffer[i] >> j) & 1);
            }
        } else if (format == 16) {
            printf("%02X", buffer[i]);
        } else if (format == 8) {
            printf("%03o", buffer[i]);
        }

        printf(" ");
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");
}

void perform_operation(unsigned char *buffer, int size, int operation) {
    unsigned char result[MAX_BUFFER];
    unsigned char operand;
    memcpy(result, buffer, size);

    if (operation == 1 || operation == 2) {
        printf("请输入操作数 (0-255): ");
        scanf("%hhu", &operand);
    }

    for (int i = 0; i < size; i++) {
        switch (operation) {
            case 1: result[i] = buffer[i] & operand; break;
            case 2: result[i] = buffer[i] | operand; break;
            case 3: result[i] = ~buffer[i]; break;
        }
    }

    printf("\n原始数据(16进制): ");
    display_binary(buffer, size, 16);
    printf("操作结果(16进制): ");
    display_binary(result, size, 16);
}

void print_menu() {
    printf("\n=== 二进制查看器 ===\n");
    printf("1. 二进制显示\n");
    printf("2. 十六进制显示\n");
    printf("3. 八进制显示\n");
    printf("4. 按位操作\n");
    printf("5. 退出\n");
    printf("请选择: ");
}
