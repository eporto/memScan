#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <fstream>
#include <iomanip>

using namespace std;

ofstream out ("test.txt");

void EnableDebugPriv()
{
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tkp;

    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);

    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = luid;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    AdjustTokenPrivileges(hToken, false, &tkp, sizeof(tkp), NULL, NULL);

    CloseHandle(hToken); 
    
}

DWORD GetProcessID(string procName) {
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    //Return INVALID_HANDLE_VALUE if failed. (obs.: 'GetLastError' for extended info)
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (Process32First(snapshot, &entry) == TRUE)
    {
        //This is skipping the first process "SYSTEM"
        while (Process32Next(snapshot, &entry) == TRUE)
        {
            if (stricmp(entry.szExeFile, procName.c_str()) == 0)
            {  
                HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);

                //cout << "Achei:" << entry.th32ProcessID << endl;
                CloseHandle(hProcess);
                cout << procName <<":"<< entry.th32ProcessID << "(0x" << setfill('0') << setw(2) << uppercase << hex <<  entry.th32ProcessID <<")"<< endl;
                return entry.th32ProcessID;
            }
        }
    }

    
    CloseHandle(snapshot);

}

void GetAddressOfData(DWORD pid)
{
    HANDLE process = OpenProcess((PROCESS_ALL_ACCESS), FALSE, pid);
    if(process)
    {
        SYSTEM_INFO si;
        GetSystemInfo(&si);

        MEMORY_BASIC_INFORMATION info;

        SIZE_T bytesRead = 0;
        INT_PTR readIndex = 0;
        int totalBytesRead = 0;
        cout << "Scanning..." << endl;
        while(true)
        {
            if(VirtualQueryEx(process, (LPCVOID)readIndex, &info, sizeof(info)) == 0) {
                cout << endl;
                cout << "Done !" << endl;
                cout << endl << "Total Bytes Read:" << dec << totalBytesRead << endl;
               /* cout << "Index:" << readIndex << endl;
                cout << "lpMaximumApplicationAddress:" << si.lpMaximumApplicationAddress << endl;*/
                break;
            }
          
            readIndex = (int)info.BaseAddress;
            //cout << readIndex << endl;
            if (!((info.State == MEM_COMMIT) ) ) {
                readIndex += info.RegionSize;
                continue;
            }

            SIZE_T bytesToRead = info.RegionSize;
            char *buffer = new char[bytesToRead];
            if(ReadProcessMemory(process, (LPCVOID)readIndex, buffer, bytesToRead, &bytesRead)) {
                for (int i = 0; i < bytesRead; i++) {
                    if (buffer[i] != '\x0')
                        out << buffer[i];
                }
                out << endl;                 
            }
            else { 
                if (bytesRead > 0) {
                    for (int i = 0; i < bytesRead; i++) {
                        if (buffer[i] != '\x0')
                            out << buffer[i];
                    }
                    out << endl;      
                }
                else {
                    bytesRead = info.RegionSize;
                }
            }
            totalBytesRead += bytesRead;
            readIndex += bytesRead;
            delete[] buffer;
        }     
    }
    //return totalsBytesRead;
}

void LocationInfo (DWORD pid, LPCVOID mem, SIZE_T numBytes) {
    HANDLE process = OpenProcess((PROCESS_ALL_ACCESS), FALSE, pid);
    if(process)
    {
        SYSTEM_INFO si;
        GetSystemInfo(&si);

        MEMORY_BASIC_INFORMATION info;

        SIZE_T bytesRead = 0;
        INT_PTR readIndex = 0;
        INT_PTR strAt = 0;
        INT_PTR lastUpdate = 0;

        cout << "Reading Address " << setfill('0') << setw(2) << hex << mem << endl;
        if(VirtualQueryEx(process, mem, &info, sizeof(info)) == 0) {
            cout << "Error VirtualQueryEx" << endl;
        }
        else {
            cout << "BaseAddress:" << setfill('0') << setw(2) << hex << info.BaseAddress << endl;
            cout << "RegionSize:" << dec << info.RegionSize << endl;
            cout << "AllocationBase:" << setfill('0') << setw(2) << hex << info.AllocationBase << endl;
            cout << "State:0x" << setfill('0') << setw(2) << hex << info.State;
            
            if (info.State == MEM_COMMIT)
                cout <<"(MEM_COMMIT)" << endl;
            else if (info.State == MEM_FREE)
                cout <<"(MEM_FREE)" << endl;
            else if (info.State == MEM_RESERVE)
                cout <<"(MEM_RESERVE)" << endl;
            else 
                cout << "(UNKNOWN)" << endl;

            //cout << "AllocationProtect:" << hex << info.AllocationProtect << endl;
            cout << "Protect:0x"  << setfill('0') << setw(2) << hex << info.Protect; 
            
            if (info.Protect == PAGE_EXECUTE_READ)
                cout <<"(PAGE_EXECUTE_READ)" << endl;
            else if (info.Protect == PAGE_EXECUTE_READWRITE)
                cout <<"(PAGE_EXECUTE_READWRITE)" << endl;
            else if (info.Protect == PAGE_EXECUTE_WRITECOPY)
                cout <<"(PAGE_EXECUTE_WRITECOPY)" << endl;
            else if (info.Protect == PAGE_NOACCESS)
                cout <<"(PAGE_NOACCESS)" << endl;
            else if (info.Protect == PAGE_READONLY)
                cout <<"(PAGE_READONLY)" << endl;
            else if (info.Protect == PAGE_READWRITE)
                cout <<"(PAGE_READWRITE)" << endl;
            else if (info.Protect == PAGE_WRITECOPY)
                cout <<"(PAGE_WRITECOPY)" << endl;
            else if (info.Protect == PAGE_GUARD)
                cout <<"(PAGE_GUARD )" << endl;
            else if (info.Protect == PAGE_EXECUTE) 
                cout << "(PAGE_EXECUTE)" << endl;
            else if (info.Protect == PAGE_NOCACHE)
                cout << "(PAGE_NOCACHE)" << endl;
            else if (info.Protect == PAGE_WRITECOMBINE)
                cout << "(PAGE_WRITECOMBINE)" << endl;
            else 
                cout << "(UNKNOWN)" << endl;

            cout << "Type:" << setfill('0') << setw(2) << hex << info.Type; 

            if (info.Type == MEM_IMAGE)
                cout <<"(MEM_IMAGE)" << endl;
            else if (info.Type == MEM_MAPPED)
                cout <<"(MEM_MAPPED)" << endl;
            else if (info.Type == MEM_PRIVATE)
                cout <<"(MEM_PRIVATE)" << endl;
            else 
                cout << "(UNKNOWN)" << endl;

            if (numBytes == 0)
                numBytes = info.RegionSize;

            char *buffer = new char[numBytes];
            //char *buffer = new char[info.RegionSize];
            cout << endl;
            if(ReadProcessMemory(process, (LPCVOID)mem, buffer, numBytes, &bytesRead)) {
                cout << "bytesRead:" << bytesRead << endl;
                    for (int i = 0; i < bytesRead; i++) {
                        if (buffer[i] != '\x0')
                            out << buffer[i];
                        cout << endl;
                    }
            }
            else {
                cout << "Error:" << GetLastError() << endl;
                cout << "bytesRead:" << bytesRead << endl;
                for (int i = 0; i < bytesRead; i++) {
                    if (buffer[i] != '\x0')
                        out << buffer[i];
                }
                cout << endl;
            }
        }
    }
}

int main(int argc, char **argv) {
    EnableDebugPriv();

    if (argc != 3 && argc != 4 && argc != 5) {
        cout << "Usage:" << endl; 
        cout << argv[0] << " <process name.exe> -scan"<< endl;
        cout << argv[0] << " <process name.exe> -meminfo <address mem> [<number of bytes>]"<< endl;
        return 1;
    }

    string procName;
    DWORD pid;
    if (argc == 3) {
        procName = argv[1];
        if(strcmp(argv[2],"-scan") == 0) {
            pid = GetProcessID(procName);
            GetAddressOfData(pid);
        }
        else {
            cout << "Wrong Syntax" << endl;
        }
    }
    else if (argc == 5) {
        procName = argv[1];
        if(strcmp(argv[2],"-meminfo") == 0 && argv[3] > 0 && argv[4] > 0) {
            pid = GetProcessID(procName);
            LPCVOID addr = (void*)strtol(argv[3], 0, 0);
            LocationInfo(pid,addr,(SIZE_T)argv[4]);
           
        }
        else {
            cout << "Wrong Syntax" << endl;
        }

    }
    else if (argc == 4) {
        procName = argv[1];
        if(strcmp(argv[2],"-meminfo") == 0 && argv[3] > 0) {
            pid = GetProcessID(procName);
            LPCVOID addr = (void*)strtol(argv[3], 0, 0);
            LocationInfo(pid,addr,0);
        }
        else {
            cout << "Wrong Syntax" << endl;
        }

    }
  
    return 0;
}