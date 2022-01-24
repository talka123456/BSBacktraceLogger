//
//  BSBacktraceLogger.m
//  BSBacktraceLogger
//
//  Created by 张星宇 on 16/8/27.
//  Copyright © 2016年 bestswifter. All rights reserved.
//

#import "BSBacktraceLogger.h"
#import <mach/mach.h>
#include <dlfcn.h>
#include <pthread.h>
#include <sys/types.h>
#include <limits.h>
#include <string.h>
#include <mach-o/dyld.h>
#include <mach-o/nlist.h>

#pragma -mark DEFINE MACRO FOR DIFFERENT CPU ARCHITECTURE
#if defined(__arm64__)
#define DETAG_INSTRUCTION_ADDRESS(A) ((A) & ~(3UL))
#define BS_THREAD_STATE_COUNT ARM_THREAD_STATE64_COUNT
#define BS_THREAD_STATE ARM_THREAD_STATE64
#define BS_FRAME_POINTER __fp
#define BS_STACK_POINTER __sp
#define BS_INSTRUCTION_ADDRESS __pc

#elif defined(__arm__)
#define DETAG_INSTRUCTION_ADDRESS(A) ((A) & ~(1UL))
#define BS_THREAD_STATE_COUNT ARM_THREAD_STATE_COUNT
#define BS_THREAD_STATE ARM_THREAD_STATE
#define BS_FRAME_POINTER __r[7]
#define BS_STACK_POINTER __sp
#define BS_INSTRUCTION_ADDRESS __pc

#elif defined(__x86_64__)
#define DETAG_INSTRUCTION_ADDRESS(A) (A)
#define BS_THREAD_STATE_COUNT x86_THREAD_STATE64_COUNT
#define BS_THREAD_STATE x86_THREAD_STATE64
#define BS_FRAME_POINTER __rbp
#define BS_STACK_POINTER __rsp
#define BS_INSTRUCTION_ADDRESS __rip

#elif defined(__i386__)
#define DETAG_INSTRUCTION_ADDRESS(A) (A)
#define BS_THREAD_STATE_COUNT x86_THREAD_STATE32_COUNT
#define BS_THREAD_STATE x86_THREAD_STATE32
#define BS_FRAME_POINTER __ebp
#define BS_STACK_POINTER __esp
#define BS_INSTRUCTION_ADDRESS __eip

#endif

#define CALL_INSTRUCTION_FROM_RETURN_ADDRESS(A) (DETAG_INSTRUCTION_ADDRESS((A)) - 1)

#if defined(__LP64__)
#define TRACE_FMT         "%-4d%-31s 0x%016lx %s + %lu"
#define POINTER_FMT       "0x%016lx"
#define POINTER_SHORT_FMT "0x%lx"
#define BS_NLIST struct nlist_64
#else
#define TRACE_FMT         "%-4d%-31s 0x%08lx %s + %lu"
#define POINTER_FMT       "0x%08lx"
#define POINTER_SHORT_FMT "0x%lx"
#define BS_NLIST struct nlist
#endif

typedef struct BSStackFrameEntry{
    const struct BSStackFrameEntry *const previous;
    const uintptr_t return_address;
} BSStackFrameEntry;

static mach_port_t main_thread_id; //!< load启动时特殊存储主线程的mach thread

@implementation BSBacktraceLogger

+ (void)load {
    main_thread_id = mach_thread_self();
}

#pragma -mark Implementation of interface

/// 获取指定线程堆栈, 是堆栈回溯的入口
/// @param thread 线程
+ (NSString *)bs_backtraceOfNSThread:(NSThread *)thread {
    return _bs_backtraceOfThread(bs_machThreadFromNSThread(thread));
}

/// 获取当前线程堆栈
+ (NSString *)bs_backtraceOfCurrentThread {
    return [self bs_backtraceOfNSThread:[NSThread currentThread]];
}

/// 获取主线程堆栈
+ (NSString *)bs_backtraceOfMainThread {
    return [self bs_backtraceOfNSThread:[NSThread mainThread]];
}


/// 获取所有线程的堆栈
+ (NSString *)bs_backtraceOfAllThread {
    thread_act_array_t threads;
    mach_msg_type_number_t thread_count = 0;
    const task_t this_task = mach_task_self();
    
    kern_return_t kr = task_threads(this_task, &threads, &thread_count);
    if(kr != KERN_SUCCESS) {
        return @"Fail to get information of all threads";
    }
    
    NSMutableString *resultString = [NSMutableString stringWithFormat:@"Call Backtrace of %u threads:\n", thread_count];
    for(int i = 0; i < thread_count; i++) {
        [resultString appendString:_bs_backtraceOfThread(threads[i])];
    }
    return [resultString copy];
}

#pragma -mark Get call backtrace of a mach_thread

/// 根据mach thread 获取调用栈回溯
/// @param thread mach thread入参
NSString *_bs_backtraceOfThread(thread_t thread) {
    // 初始化50长度的指针数组
    uintptr_t backtraceBuffer[50];
    int i = 0;
    NSMutableString *resultString = [[NSMutableString alloc] initWithFormat:@"Backtrace of Thread %u:\n", thread];
    
    // 线程上下文结构体, 不同cpu结构不同, 所以用宏做了处理
    _STRUCT_MCONTEXT machineContext;
    if(!bs_fillThreadStateIntoMachineContext(thread, &machineContext)) {
        return [NSString stringWithFormat:@"Fail to get information about thread: %u", thread];
    }
    
    //instruction 指令地址, 即pc指针, 这里记录pc的目的是什么? 由于没有办法获取到当前调用栈的符号, 所以通过pc作为查询最近符号的指令地址
    const uintptr_t instructionAddress = bs_mach_instructionAddress(&machineContext);
    backtraceBuffer[i] = instructionAddress;
    ++i;
    
    // 这里为什么要在调用栈里先存储lr呢? 和索引2不会重复吗
//    uintptr_t linkRegister = bs_mach_linkRegister(&machineContext);
//    if (linkRegister) {
//        backtraceBuffer[i] = linkRegister;
//        i++;
//    }
    
    if(instructionAddress == 0) {
        return @"Fail to get instruction address";
    }
    
    // 自定义的帧实体链表, 存储上一个调用栈以及返回地址(lr)
    BSStackFrameEntry frame = {0};
    
    // fp指针
    const uintptr_t framePtr = bs_mach_framePointer(&machineContext);
    if(framePtr == 0 ||
       // 将fp存储的内容 (pre fp指针)存储到previous, fp+1 存储的内容(lr)存储到return_address
       bs_mach_copyMem((void *)framePtr, &frame, sizeof(frame)) != KERN_SUCCESS) {
        return @"Fail to get frame pointer";
    }
    
    // 只存储50个调用栈, 防止调用栈过大(例如死循环)
    // 原理就是通过当前栈帧的fp读取下一个指针数据,记录的是上一个栈帧的fp数据, fp + 2,存储的是lr数据, 即当前栈退栈后的返回地址(bl的下一条指令地址)
    for(; i < 50; i++) {
        backtraceBuffer[i] = frame.return_address;
        if(backtraceBuffer[i] == 0 ||
           frame.previous == 0 ||
           bs_mach_copyMem(frame.previous, &frame, sizeof(frame)) != KERN_SUCCESS) {
            break;
        }
    }
    
    // 开始做符号化
    int backtraceLength = i;
    Dl_info symbolicated[backtraceLength];
    
    bs_symbolicate(backtraceBuffer, symbolicated, backtraceLength, 0);
    
    // 打印结果
    for (int i = 0; i < backtraceLength; ++i) {
        [resultString appendFormat:@"%@", bs_logBacktraceEntry(i, backtraceBuffer[i], &symbolicated[i])];
    }
    [resultString appendFormat:@"\n"];
    return [resultString copy];
}

#pragma -mark Convert NSThread to Mach thread

/// NSThread ==> thread 映射关系
/// @param nsthread 上层的NSThread 线程对象, 通过线程名称映射
thread_t bs_machThreadFromNSThread(NSThread *nsthread) {
    char name[256];
    mach_msg_type_number_t count;
    thread_act_array_t list;
    
    // tash_thread 是内核提供的api 获取所有线程对象, 这里获取到的是mach 线程
    task_threads(mach_task_self(), &list, &count);
    
    // 用时间戳重置线程名称用于匹配, 主线程设置 name 后无法用 pthread_getname_np 读取,需要特殊处理
    NSTimeInterval currentTimestamp = [[NSDate date] timeIntervalSince1970];
    // 保存线程名称, 用户后续恢复
    NSString *originName = [nsthread name];
    [nsthread setName:[NSString stringWithFormat:@"%f", currentTimestamp]];
    
    // 如果是主线程, 主线程设置 name 后无法用 pthread_getname_np 读取,导致后续思路无法走通, 所以这里直接返回load时获取的主线程对应的mach thread
    if ([nsthread isMainThread]) {
        return (thread_t)main_thread_id;
    }
    
    for (int i = 0; i < count; ++i) {
        pthread_t pt = pthread_from_mach_thread_np(list[i]);
        if ([nsthread isMainThread]) {
            if (list[i] == main_thread_id) {
                return list[i];
            }
        }
        if (pt) {
            // c字符串以\0结束
            name[0] = '\0';
            
            // 获取mach thread 名称
            pthread_getname_np(pt, name, sizeof name);
            // strcmp() 传入字符串相等时 == 0, 这里取反表示 相等时执行
            if (!strcmp(name, [nsthread name].UTF8String)) {
                [nsthread setName:originName];
                return list[i];
            }
        }
    }
    
    // 恢复线程名
    [nsthread setName:originName];
    
    // 返回当前执行线程对应的mach thread保底
    return mach_thread_self();
}

#pragma -mark GenerateBacbsrackEnrty
NSString* bs_logBacktraceEntry(const int entryNum,
                               const uintptr_t address,
                               const Dl_info* const dlInfo) {
    char faddrBuff[20];
    char saddrBuff[20];
    
    const char* fname = bs_lastPathEntry(dlInfo->dli_fname);
    if(fname == NULL) {
        sprintf(faddrBuff, POINTER_FMT, (uintptr_t)dlInfo->dli_fbase);
        fname = faddrBuff;
    }
    
    uintptr_t offset = address - (uintptr_t)dlInfo->dli_saddr;
    const char* sname = dlInfo->dli_sname;
    if(sname == NULL) {
        sprintf(saddrBuff, POINTER_SHORT_FMT, (uintptr_t)dlInfo->dli_fbase);
        sname = saddrBuff;
        offset = address - (uintptr_t)dlInfo->dli_fbase;
    }
    return [NSString stringWithFormat:@"%-30s  0x%08" PRIxPTR " %s + %lu\n" ,fname, (uintptr_t)address, sname, offset];
}

const char* bs_lastPathEntry(const char* const path) {
    if(path == NULL) {
        return NULL;
    }
    
    char* lastFile = strrchr(path, '/');
    return lastFile == NULL ? path : lastFile + 1;
}

#pragma -mark HandleMachineContext
// 通过thread_get_state 获取线程上下文对象, 并返回结果状态
bool bs_fillThreadStateIntoMachineContext(thread_t thread, _STRUCT_MCONTEXT *machineContext) {
    // BS_THREAD_STATE_COUNT 根据不同的cpu有不同的定义, 这是由于不同的架构thread_get_state获取参数不一致导致的,
    mach_msg_type_number_t state_count = BS_THREAD_STATE_COUNT;
    // thread_get_state 两个入参和cpu有关, 所以定义了BS_THREAD_STATE 和 BS_THREAD_STATE_COUNT
    kern_return_t kr = thread_get_state(thread, BS_THREAD_STATE, (thread_state_t)&machineContext->__ss, &state_count);
    return (kr == KERN_SUCCESS);
}

// 获取fp指针
uintptr_t bs_mach_framePointer(mcontext_t const machineContext){
    return machineContext->__ss.BS_FRAME_POINTER;
}

// 获取sp指针
uintptr_t bs_mach_stackPointer(mcontext_t const machineContext){
    return machineContext->__ss.BS_STACK_POINTER;
}

// pc寄存器, 存储即将执行的指令地址
uintptr_t bs_mach_instructionAddress(mcontext_t const machineContext){
    return machineContext->__ss.BS_INSTRUCTION_ADDRESS;
}

// 获取lr指针 32位和64位x86 不存在该指针, 是在call时 储存在调用者的栈帧里, 可以参考https://www.jianshu.com/p/8ece78d71b3d中,x86和arm的对比
uintptr_t bs_mach_linkRegister(mcontext_t const machineContext){
#if defined(__i386__) || defined(__x86_64__)
    return 0;
#else
    return machineContext->__ss.__lr;
#endif
}

/// 读取虚拟内存
/// @param src 读取地址
/// @param dst 拷贝到数据结构
/// @param numBytes 读取字节数,
kern_return_t bs_mach_copyMem(const void *const src, void *const dst, const size_t numBytes){
    vm_size_t bytesCopied = 0;
    /**
    vm_read_overwrite()会首先询问内核是否可以访问内存,因此它不会崩溃.
    kern_return_t vm_read_overwrite
    (
        vm_map_t target_task,  //task任务
        vm_address_t address,  //栈帧指针FP
        vm_size_t size,  //结构体大小 sizeof（StackFrameEntry）
        vm_address_t data,  //结构体指针StackFrameEntry
        vm_size_t *outsize  //赋值大小
    );
    */
    return vm_read_overwrite(mach_task_self(), (vm_address_t)src, (vm_size_t)numBytes, (vm_address_t)dst, &bytesCopied);
}

#pragma -mark Symbolicate

/// 函数地址符号化
/// @param backtraceBuffer lr指令数组
/// @param symbolsBuffer 符号数组
/// @param numEntries 长度
/// @param skippedEntries 0
void bs_symbolicate(const uintptr_t* const backtraceBuffer,
                    Dl_info* const symbolsBuffer,
                    const int numEntries,
                    const int skippedEntries){
    int i = 0;
    
    // TODO:hw skippedEntries的作用?
    if(!skippedEntries && i < numEntries) {
        bs_dladdr(backtraceBuffer[i], &symbolsBuffer[i]);
        i++;
    }
    
    for(; i < numEntries; i++) {
        /**
         DETAG_INSTRUCTION_ADDRESS
         为了去掉指令地址中的指针标签。因为ARMv7 中的地址分为Thumb Mode 和 Normal Mode，对应的指令地址分别是2字节 和 4字节，arm64下指令地址都是4字节，（按照4字节对齐存储，一条指令必须从4的整数倍地址来取）所以指令地址的最后2 bits 肯定都是0，系统一般会在这后两位中插入一个指针标签，要去掉这个标签的值才是真正的指令地址。而x86_64中指令是可变长度的，所有的bits 都是有意义的。
         这个宏的作用就是为了适配x86 和 arm平台的指令处理方式不同。
         
         */
        bs_dladdr(CALL_INSTRUCTION_FROM_RETURN_ADDRESS(backtraceBuffer[i]), &symbolsBuffer[i]);
    }
}

/// 从地址获取符号, 等价于系统API dladdr()
/// @param address 地址
/// @param info dyld_info结构体
bool bs_dladdr(const uintptr_t address, Dl_info* const info) {
    info->dli_fname = NULL;
    info->dli_fbase = NULL;
    info->dli_sname = NULL;
    info->dli_saddr = NULL;
    
    // 获取指定地址所在的镜像的索引值
    const uint32_t idx = bs_imageIndexContainingAddress(address);
    
    // 异常退出
    if(idx == UINT_MAX) {
        return false;
    }
    
    // 获取MachO header
    const struct mach_header* header = _dyld_get_image_header(idx);
    
    // 获取aslr偏移地址
    const uintptr_t imageVMAddrSlide = (uintptr_t)_dyld_get_image_vmaddr_slide(idx);
    
    // 获取地址的MachO中真实地址(减去aslr的)
    const uintptr_t addressWithSlide = address - imageVMAddrSlide;
    
    // bs_segmentBaseOfImageIndex 获取的PageZero的地址, 默认是0x 1 0000 0000
    // segmentBase是segment的基地址(aslr + pagezero), 其实这个值就是header的起始地址 header  = PageZero + ASLR
    const uintptr_t segmentBase = bs_segmentBaseOfImageIndex(idx) + imageVMAddrSlide;
    if(segmentBase == 0) {
        return false;
    }
    
    info->dli_fname = _dyld_get_image_name(idx);
    info->dli_fbase = (void*)header;
    
    // Find symbol tables and get whichever symbol is closest to the address.
    const BS_NLIST* bestMatch = NULL;
    uintptr_t bestDistance = ULONG_MAX;
    
    // header后的首个load command地址
    uintptr_t cmdPtr = bs_firstCmdAfterHeader(header);
    if(cmdPtr == 0) {
        return false;
    }
    for(uint32_t iCmd = 0; iCmd < header->ncmds; iCmd++) {
        const struct load_command* loadCmd = (struct load_command*)cmdPtr;
        
        // LC_SYMTAB 该cmd存储的是符号相关的内容
        if(loadCmd->cmd == LC_SYMTAB) {
            // 转为symtab_command结构体
            const struct symtab_command* symtabCmd = (struct symtab_command*)cmdPtr;
            /**
             This is the symbol table entry structure for 64-bit architectures.
             struct nlist_64 {
                 union {
                     uint32_t  n_strx;  i// ndex into the string table
                 } n_un;
                 uint8_t n_type;    //  type flag, see below
                 uint8_t n_sect;        /// section number or NO_SECT
                 uint16_t n_desc;       // see <mach-o/stab.h>
                 uint64_t n_value;      // value of this symbol (or stab offset)
             };
            */
            // 符号表地址(内存中真实虚拟地址)
            const BS_NLIST* symbolTable = (BS_NLIST*)(segmentBase + symtabCmd->symoff);
            
            // 字符串表的真实地址
            const uintptr_t stringTable = segmentBase + symtabCmd->stroff;
            
            for(uint32_t iSym = 0; iSym < symtabCmd->nsyms; iSym++) {
                // If n_value is 0, the symbol refers to an external object.
                if(symbolTable[iSym].n_value != 0) {
                    // 符号地址
                    uintptr_t symbolBase = symbolTable[iSym].n_value;
                    
                    // 计算lr指令地址和符号地址的地址距离
                    uintptr_t currentDistance = addressWithSlide - symbolBase;
                    // 指令地址 > 符号地址, 并且距离消息最佳距离, 则更新最佳距离以及匹配符号
                    if((addressWithSlide >= symbolBase) &&
                       (currentDistance <= bestDistance)) {
                        // 这里为什么用symbolTable + iSym? 结构体指针 + num 表示按照结构体指针大小偏移内容
                        bestMatch = symbolTable + iSym;
                        bestDistance = currentDistance;
                    }
                }
            }
            
            // 匹配到符号表结构, 从字符串表中读取符号对应的名称
            if(bestMatch != NULL) {
                // 符号地址(真是内存中的, 加上ASLR后的地址)
                info->dli_saddr = (void*)(bestMatch->n_value + imageVMAddrSlide);
                
                // 获取符号在字符串表中的内容
                info->dli_sname = (char*)((intptr_t)stringTable + (intptr_t)bestMatch->n_un.n_strx);
                if(*info->dli_sname == '_') {
                    info->dli_sname++;
                }
                // This happens if all symbols have been stripped.
                if(info->dli_saddr == info->dli_fbase && bestMatch->n_type == 3) {
                    info->dli_sname = NULL;
                }
                break;
            }
        }
        cmdPtr += loadCmd->cmdsize;
    }
    return true;
}

/// 通过header 获取load command 的指针地址
/// @param header header 的指针地址
uintptr_t bs_firstCmdAfterHeader(const struct mach_header* const header) {
    switch(header->magic) {
        case MH_MAGIC:
        case MH_CIGAM:
            return (uintptr_t)(header + 1);
        case MH_MAGIC_64:
        case MH_CIGAM_64:
            return (uintptr_t)(((struct mach_header_64*)header) + 1);
        default:
            return 0;  // Header is corrupt
    }
}

/// 从地址中获取所在镜像的索引值
/// @param address 地址
uint32_t bs_imageIndexContainingAddress(const uintptr_t address) {
    // 通过dyld函数获取镜像数量
    const uint32_t imageCount = _dyld_image_count();
    const struct mach_header* header = 0;
    
    for(uint32_t iImg = 0; iImg < imageCount; iImg++) {
        // Mach Header
        header = _dyld_get_image_header(iImg);
        if(header != NULL) {
            // Look for a segment command with this address within its range.
            // 通过lr - 镜像虚拟偏移基地址, 获得偏移量, 用偏移量计算出在哪个segment
            uintptr_t addressWSlide = address - (uintptr_t)_dyld_get_image_vmaddr_slide(iImg);
            
            // 获取Mach Header magic 魔数, 这里是为了区分cpu架构 64位是mach_header_64类型, 32位是mach_header类型
            uintptr_t cmdPtr = bs_firstCmdAfterHeader(header);
            if(cmdPtr == 0) {
                continue;
            }
            
            for(uint32_t iCmd = 0; iCmd < header->ncmds; iCmd++) {
                const struct load_command* loadCmd = (struct load_command*)cmdPtr;
                // 区分32 / 64位架构, 判断偏移地址是否在当前cmd 起始和终止的区间内
                if(loadCmd->cmd == LC_SEGMENT) {
                    const struct segment_command* segCmd = (struct segment_command*)cmdPtr;
                    if(addressWSlide >= segCmd->vmaddr &&
                       addressWSlide < segCmd->vmaddr + segCmd->vmsize) {
                        return iImg;
                    }
                }
                else if(loadCmd->cmd == LC_SEGMENT_64) {
                    const struct segment_command_64* segCmd = (struct segment_command_64*)cmdPtr;
                    if(addressWSlide >= segCmd->vmaddr &&
                       addressWSlide < segCmd->vmaddr + segCmd->vmsize) {
                        return iImg;
                    }
                }
                // cmd地址指针指向下一个cmd的地址, cmdsize为cmd占用的大小, cmd是连续的所以next cmd = cmd + size
                cmdPtr += loadCmd->cmdsize;
            }
        }
    }
    
    // 默认返回极值
    return UINT_MAX;
}

/// 获取特定segment __LINKEDIT 的基地址,  个人理解,直接通过Header获取pagezero一样的目的
/// @param idx 镜像索引值
uintptr_t bs_segmentBaseOfImageIndex(const uint32_t idx) {
    const struct mach_header* header = _dyld_get_image_header(idx);
    
    // Look for a segment command and return the file image address.
    // 获取Command 地址 MachO格式为header -> Load Command -> segment, 所以header+1即load command的指针地址
    uintptr_t cmdPtr = bs_firstCmdAfterHeader(header);
    if(cmdPtr == 0) {
        return 0;
    }
    
    for(uint32_t i = 0;i < header->ncmds; i++) {
        const struct load_command* loadCmd = (struct load_command*)cmdPtr;
        if(loadCmd->cmd == LC_SEGMENT) {
            const struct segment_command* segmentCmd = (struct segment_command*)cmdPtr;
            if(strcmp(segmentCmd->segname, SEG_LINKEDIT) == 0) {
                return segmentCmd->vmaddr - segmentCmd->fileoff;
            }
        }
        else if(loadCmd->cmd == LC_SEGMENT_64) {
            const struct segment_command_64* segmentCmd = (struct segment_command_64*)cmdPtr;
            if(strcmp(segmentCmd->segname, SEG_LINKEDIT) == 0) {
                return (uintptr_t)(segmentCmd->vmaddr - segmentCmd->fileoff);
            }
        }
        cmdPtr += loadCmd->cmdsize;
    }
    return 0;
}

@end
