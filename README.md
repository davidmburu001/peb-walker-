PEB WALKER WITH API HASHING

So i am going to go through how to write an assembly code for walking the peb.Walking the peb is often used in exploit developement and malware developement to resolve functions but modern AVs and EDR can still flag them as malicious.So lets dive into it.

This program walks peb and resolve WinExec() address and pops Calc.

```What is PEB```
Every process contains a ```_EPROCESS``` structure created by windows loader(LDR).Another big process maybe we can talk about it another day.The _EPROCESS structure contains helpful structure needed by the process to run eg it contains parameters for the process,flags supplied when calling ```CreateProcess``` and other structures but most importantly ut contains a structure known as ```PEB```(Process Enviroment Block)

```
C
struct EPROCESS{
    struct _KPROCESS Pcb; //0x0
    struct _EX_PUSH_LOCK ProcessLock; //0x160
    union _LARGE_INTEGER CreateTime; //0x168
    union _LARGE_INTEGER ExitTime; //0x170
    struct _EX_RUNDOWN_REF RundownProtect; //0x178
    VOID* UniqueProcessId; //0x180
    struct _LIST_ENTRY ActiveProcessLinks; //0x188
    ULONGLONG ProcessQuotaUsage[2]; //0x198
    ULONGLONG ProcessQuotaPeak[2]; //0x1a8
    volatile ULONGLONG CommitCharge; //0x1b8
    struct _EPROCESS_QUOTA_BLOCK * QuotaBlock; //0x1c0
    struct _PS_CPU_QUOTA_BLOCK * CpuQuotaBlock; //0x1c8
    ULONGLONG PeakVirtualSize; //0x1d0
    ULONGLONG VirtualSize; //0x1d8
    struct _LIST_ENTRY SessionProcessLinks; //0x1e0
    VOID* DebugPort; //0x1f0
    union{
        VOID * ExceptionPortData; //0x1f8
        ULONGLONG ExceptionPortValue; //0x1f8
        ULONGLONG ExceptionPortState:3; //0x1f8
        };
    struct _HANDLE_TABLE * ObjectTable; //0x200
    struct _EX_FAST_REF Token; //0x208
    ULONGLONG WorkingSetPage; //0x210
    struct _EX_PUSH_LOCK AddressCreationLock; //0x218
    struct _ETHREAD * RotateInProgress; //0x220
    struct _ETHREAD * ForkInProgress; //0x228
    ULONGLONG HardwareTrigger; //0x230
    struct _MM_AVL_TABLE * PhysicalVadRoot; //0x238
    VOID* CloneRoot; //0x240
    volatile ULONGLONG NumberOfPrivatePages; //0x248
    volatile ULONGLONG NumberOfLockedPages; //0x250
    VOID* Win32Process; //0x258
    struct _EJOB * volatile Job; //0x260
    VOID* SectionObject; //0x268
    VOID* SectionBaseAddress; //0x270
    ULONG Cookie; //0x278
    ULONG UmsScheduledThreads; //0x27c
    struct _PAGEFAULT_HISTORY * WorkingSetWatch; //0x280
    VOID* Win32WindowStation; //0x288
    VOID* InheritedFromUniqueProcessId; //0x290
    VOID* LdtInformation; //0x298
    VOID* Spare; //0x2a0
    ULONGLONG ConsoleHostProcess; //0x2a8
    VOID* DeviceMap; //0x2b0
    VOID* EtwDataSource; //0x2b8
    VOID* FreeTebHint; //0x2c0
    VOID* FreeUmsTebHint; //0x2c8
    union{
        struct _HARDWARE_PTE PageDirectoryPte; //0x2d0
        ULONGLONG Filler; //0x2d0
        };
    VOID* Session; //0x2d8
    UCHAR ImageFileName[15]; //0x2e0
    UCHAR PriorityClass; //0x2ef
    struct _LIST_ENTRY JobLinks; //0x2f0
    VOID* LockedPagesList; //0x300
    struct _LIST_ENTRY ThreadListHead; //0x308
    VOID* SecurityPort; //0x318
    VOID* Wow64Process; //0x320
    volatile ULONG ActiveThreads; //0x328
    ULONG ImagePathHash; //0x32c
    ULONG DefaultHardErrorProcessing; //0x330
    LONG LastThreadExitStatus; //0x334

    struct _PEB * Peb; //0x338
    struct _EX_FAST_REF PrefetchTrace; //0x340
    union _LARGE_INTEGER ReadOperationCount; //0x348
    union _LARGE_INTEGER WriteOperationCount; //0x350
    union _LARGE_INTEGER OtherOperationCount; //0x358
    union _LARGE_INTEGER ReadTransferCount; //0x360
    union _LARGE_INTEGER WriteTransferCount; //0x368
    union _LARGE_INTEGER OtherTransferCount; //0x370
    ULONGLONG CommitChargeLimit; //0x378
    volatile ULONGLONG CommitChargePeak; //0x380
    VOID* AweInfo; //0x388
    struct _SE_AUDIT_PROCESS_CREATION_INFO SeAuditProcessCreationInfo; //0x390
    struct _MMSUPPORT Vm; //0x398
    struct _LIST_ENTRY MmProcessLinks; //0x420
    VOID* HighestUserAddress; //0x430
    ULONG ModifiedPageCount; //0x438
    union{
        ULONG Flags2; //0x43c
        struct{
            ULONG JobNotReallyActive:1; //0x43c
            ULONG AccountingFolded:1; //0x43c
            ULONG NewProcessReported:1; //0x43c
            ULONG ExitProcessReported:1; //0x43c
            ULONG ReportCommitChanges:1; //0x43c
            ULONG LastReportMemory:1; //0x43c
            ULONG ReportPhysicalPageChanges:1; //0x43c
            ULONG HandleTableRundown:1; //0x43c
            ULONG NeedsHandleRundown:1; //0x43c
            ULONG RefTraceEnabled:1; //0x43c
            ULONG NumaAware:1; //0x43c
            ULONG ProtectedProcess:1; //0x43c
            ULONG DefaultPagePriority:3; //0x43c
            ULONG PrimaryTokenFrozen:1; //0x43c
            ULONG ProcessVerifierTarget:1; //0x43c
            ULONG StackRandomizationDisabled:1; //0x43c
            ULONG AffinityPermanent:1; //0x43c
            ULONG AffinityUpdateEnable:1; //0x43c
            ULONG PropagateNode:1; //0x43c
            ULONG ExplicitAffinity:1; //0x43c
        };
    };
    union{
        ULONG Flags; //0x440
        struct{
            ULONG CreateReported:1; //0x440
            ULONG NoDebugInherit:1; //0x440
            ULONG ProcessExiting:1; //0x440
            ULONG ProcessDelete:1; //0x440
            ULONG Wow64SplitPages:1; //0x440
            ULONG VmDeleted:1; //0x440
            ULONG OutswapEnabled:1; //0x440
            ULONG Outswapped:1; //0x440
            ULONG ForkFailed:1; //0x440
            ULONG Wow64VaSpace4Gb:1; //0x440
            ULONG AddressSpaceInitialized:2; //0x440
            ULONG SetTimerResolution:1; //0x440
            ULONG BreakOnTermination:1; //0x440
            ULONG DeprioritizeViews:1; //0x440
            ULONG WriteWatch:1; //0x440
            ULONG ProcessInSession:1; //0x440
            ULONG OverrideAddressSpace:1; //0x440
            ULONG HasAddressSpace:1; //0x440
            ULONG LaunchPrefetched:1; //0x440
            ULONG InjectInpageErrors:1; //0x440
            ULONG VmTopDown:1; //0x440
            ULONG ImageNotifyDone:1; //0x440
            ULONG PdeUpdateNeeded:1; //0x440
            ULONG VdmAllowed:1; //0x440
            ULONG CrossSessionCreate:1; //0x440
            ULONG ProcessInserted:1; //0x440
            ULONG DefaultIoPriority:3; //0x440
            ULONG ProcessSelfDelete:1; //0x440
            ULONG SetTimerResolutionLink:1; //0x440
        };
    };
    LONG ExitStatus; //0x444
    struct _MM_AVL_TABLE VadRoot; //0x448
    struct _ALPC_PROCESS_CONTEXT AlpcContext; //0x488
    struct _LIST_ENTRY TimerResolutionLink; //0x4a8
    ULONG RequestedTimerResolution; //0x4b8
    ULONG ActiveThreadsHighWatermark; //0x4bc
    ULONG SmallestTimerResolution; //0x4c0
    struct _PO_DIAG_STACK_RECORD * TimerResolutionStackRecord; //0x4c8
};
```

so that is the EPROCESS Structure.As the name suggests,EPROCESS(Executive Process ) is a kernel mode structure and you cannot view it or use it when user mode.Obviously we need a Structure in user mode sibce we sometimes need some information in user mode and more so in windbg or cdb debuggers when viewing a process using ```!process``` command in user mode you can see the EPROCESS  structure.So windows created a structure called Process enviroment block(PEB) which has fields that are necessary/needed in user mode.
For our goal which is peb walking we will need peb and we need to access it in our assembly code at runtime.
There is another Structure Called Thread enviroment block(TEB) that can also be accessed in usermode.TEB contains important information about a thread and another interesting thing it contains a pointer to PEB of its process at offset 0x60(64 bit)  mostly in x64 systems and offset 0x30 at x86(32 bit) systems.The good thing is we can access TEB through a register though it is a module specific register(MDR) called gs.GS is an interesting register since in it you can access two different structures depending on the mode(user or kernel)that you are in.
GS register can contains values like C00000101 which denotes a GS_BASE meaninv youa are in user mode so when querying gs now you get TEB.It can also contains C00000102 which is a KERNEL_GS_BASE so if you query it now you get a structure known as KPCR(kernel processor control region) containing information about the processor.SWAPGS assembly instruction is the one used to change the values in gs register and since its a "priviledge escalation" instruction it is mostly used by system services or processes.
So if gc can contain a pointer to TEB that means we can use it to get TEB and then we get PEB.Its much easy
```
assembly
push rbp  
mov rbp,rsp 
sub rsp,48

xor r11,r11
mov r11,gs:[r11+0x60]
```
As you can see we have gotten the pointer to PEB with just one instruction ```mov r11,gs:[r11+0x60]```.so we are using gs to get TEB and then at TEB[0x60] is where we have our PEB pointer.I xored r11 to itself so it has value 0,i added it to 0x60 to avoid null bytes in my opcodes.

so after getting PEB whats next?In PEB structure there is a field in it which is apointer to LDR modules.LDR modules are how modules such as dlls abd executables are loaded in order.There are three ways they are loaded:

1:```InLoadOrderModuleList```-how they are loaded from first to last
2:```InMemoryOrderModuleList```-how they are in memory
3:```InInitializationOrderModuleList```-how they are initialized

so you can use any of the _PEB_LDR to get a dll or module that we want.I prefer to use ```InLoadOrderModuleList```.So first we access the _PEB_LDR structure at offset 0x18 from peb and then access the Inloadordermodule list at ofsset 0x10 in _PEB_LDR:

```
assembly
mov r11,[r11+0x18];PEB_LDR
mov r11,[r11+0x10];inordermodulelist
```

in InorderModuleList the first list in the _PEB_LDR_DATA is always the process executable itself,then ntdll,kernel32 and so on.But here we need kernel32.dll so we need to iterate the list upto the third list.
```
assembly

mov r11,[r11] ;ntdll
mov r11,[r11] ;kernel32
mov r12,[r11+0x20] ;DllBase
```
we use 0x20 to get the dllbase of kernel32.dll.
after now getting the base address of dll we need to get PE structure from it so that we can get EXPORT_ADDRESS_TABLE so that we can resolve functions.
```
assembly
mov r10,[r11+0x3C];PE
add r10,r11
mov r12,[r10+0x88];Export table
add r12,r11

```

we add 0x3c to the dll base to get pe header and theb add 0x88 to get EXPORT_ADDRESD_TABLE.So having a pointer to EAT now we can use to get a list of all the functions exported by kernel32.dll.
EXPORT_ADDRESS_TABLE contains fields such as number of functions at offset 0x10,address of function at offset 0x1C,address of names at offset 0x20,address of ordinal names at offset 0x24
```
![EAT](windbg)
```
so we use all those in finding a functionas i did in the walk.asm and so on.


The last thing that i want to talk about is the hashing of strings i used.Hashing is used to avoid forensic analysts using tools  such as process explorer to observe the strings you used in your code since strings are very important forensics on an attacker.So for me i used ROR13 hashing algorithm where i ROR(rotate write) the string making them unreadable to humans and then i hash all function codes in EAT and compare them to tge function i want.This code would be detected by EDR so its not that much complicated maybe i will add other techniques for bypassing EDR one day.Techniques like using syscall,buble sort and so on.

