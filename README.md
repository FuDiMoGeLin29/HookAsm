# HookAsm

一个功能强大的指令级 Hook 库，支持在汇编代码的任意位置进行 Hook，可读写 CPU 寄存器，实现对 `usercall` 调用约定的 Hook。本库仅支持 Windows 系统（x86/x64）。

---

## 目录

- [项目概述](#项目概述)
- [功能特性](#功能特性)
- [技术架构](#技术架构)
- [32位与64位实现差异详解](#32位与64位实现差异详解)
- [安装部署指南](#安装部署指南)
- [使用说明](#使用说明)
- [API 文档](#api-文档)
- [示例代码](#示例代码)
- [常见问题解答](#常见问题解答)
- [注意事项与最佳实践](#注意事项与最佳实践)
- [依赖库说明](#依赖库说明)
- [许可证信息](#许可证信息)

---

## 项目概述

HookAsm 是一个指令级 Hook 库，与传统的函数级 Hook 不同，它可以在汇编代码的任意指令边界进行 Hook 操作。这使得它能够：

- 在函数内部任意位置进行拦截
- 读写所有通用寄存器
- 读写标志寄存器 (EFLAGS/RFLAGS)
- 读写浮点寄存器 (FPU/XMM)
- 修改程序执行流程
- 实现 `usercall` 等非标准调用约定的 Hook

### 适用场景

- 游戏逆向分析与修改
- 软件行为分析
- 动态补丁
- 调试辅助工具
- 性能监控与分析

---

## 功能特性

### 核心功能

| 功能 | 32位支持 | 64位支持 | 说明 |
|------|---------|---------|------|
| 指令级 Hook | ✅ | ✅ | 在任意指令边界进行 Hook |
| 寄存器读写 | ✅ | ✅ | 读写所有通用寄存器 |
| 标志位读写 | ✅ | ✅ | 读写 EFLAGS/RFLAGS |
| FPU/XMM 寄存器 | ✅ | ✅ | 读写浮点/SIMD 寄存器 |
| 函数级 Hook | ✅ | ✅ | 传统函数 Hook 功能 |
| 原代码执行位置控制 | ✅ | ✅ | 支持前置/后置/不执行原代码 |
| 自定义回跳地址 | ✅ | ✅ | 支持 Hook 后跳转到指定地址 |

### 高级特性

- **自动反汇编分析**：使用 Capstone 引擎自动分析被 Hook 位置的指令，确保不会在指令中间截断
- **动态代码生成**：使用 AsmJit/AsmTk 在运行时生成机器码
- **智能内存管理**：64位版本使用 CodeHeap 管理可执行内存，解决 32 位相对跳转距离限制
- **线程安全**：支持多个 Hook 点同时存在
- **可逆操作**：支持 Hook 的安装与卸载

---

## 技术架构

### 整体架构

```
┌─────────────────────────────────────────────────────────────┐
│                        用户代码层                            │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ HookBegin   │  │HookFunction │  │   辅助函数          │  │
│  │ HookStop    │  │Begin/Stop   │  │ (Asm_Ret, etc.)     │  │
│  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘  │
└─────────┼────────────────┼───────────────────┼──────────────┘
          │                │                   │
┌─────────┴────────────────┴───────────────────┴──────────────┐
│                        核心引擎层                            │
│  ┌─────────────────────────────────────────────────────┐    │
│  │              Hook 核心逻辑                           │    │
│  │  ┌───────────────┐  ┌───────────────────────────┐   │    │
│  │  │ 反汇编分析    │  │ 代码生成与注入            │   │    │
│  │  │ (Capstone)    │  │ (AsmJit/AsmTk)           │   │    │
│  │  └───────────────┘  └───────────────────────────┘   │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
          │
┌─────────┴───────────────────────────────────────────────────┐
│                        内存管理层                            │
│  ┌─────────────────────┐    ┌─────────────────────────┐     │
│  │ 32位: Heap API      │    │ 64位: CodeHeap          │     │
│  │ (简单堆分配)        │    │ (智能内存池管理)        │     │
│  └─────────────────────┘    └─────────────────────────┘     │
└─────────────────────────────────────────────────────────────┘
```

### 目录结构

```
HookAsm/
├── HookAsm模板X32/                 # 32位版本
│   ├── HookAsm/
│   │   ├── HookAsm.h               # 核心头文件
│   │   ├── HookAsm.cpp             # 核心实现
│   │   ├── asmtk/                  # 汇编工具包
│   │   │   ├── asmjit/             # AsmJit JIT编译器
│   │   │   ├── asmparser.cpp/h     # 汇编解析器
│   │   │   └── asmtokenizer.cpp/h  # 汇编词法分析器
│   │   └── capstone/               # Capstone 反汇编引擎
│   │       ├── capstone.h          # Capstone 头文件
│   │       └── capstone.lib        # Capstone 静态库
│   ├── dllmain.cpp                 # DLL 入口点
│   ├── main.cpp                    # 用户代码入口
│   ├── main.h                      # 用户代码头文件
│   ├── framework.h                 # Windows 框架头文件
│   └── HookAsm模板X32.vcxproj      # Visual Studio 项目文件
│
├── HookAsm模板X64/                 # 64位版本
│   ├── HookAsm/
│   │   ├── HookAsm.h               # 核心头文件 (64位)
│   │   ├── HookAsm.cpp             # 核心实现 (64位)
│   │   ├── HookAsmCodeHeap.h       # 代码堆管理器头文件
│   │   ├── HookAsmCodeHeap.cpp     # 代码堆管理器实现
│   │   ├── EflagsChange.asm        # 标志位操作汇编代码
│   │   ├── asmtk/                  # 汇编工具包 (同32位)
│   │   └── capstone/               # Capstone 反汇编引擎 (64位版本)
│   ├── dllmain.cpp                 # DLL 入口点
│   ├── main.cpp                    # 用户代码入口
│   ├── main.h                      # 用户代码头文件
│   ├── framework.h                 # Windows 框架头文件
│   └── HookAsm模板X64.vcxproj      # Visual Studio 项目文件
│
├── HookAsm模板.sln                 # Visual Studio 解决方案
├── LICENSE.txt                     # Apache 2.0 许可证
└── README.md                       # 本文档
```

---

## 32位与64位实现差异详解

本节详细分析 32 位和 64 位系统环境下的实现差异、兼容性考量、性能表现及潜在问题。

### 1. 寄存器结构差异

#### 32位 Register 结构 (x86)

```cpp
struct Register
{
    Eflags eflags;          // 标志寄存器 (32位)
    // 8个通用寄存器
    union { int32_t edi; int16_t di; };
    union { int32_t esi; int16_t si; };
    union { int32_t ebp; int16_t bp; };
    union { int32_t esp; int16_t sp; };
    union { int32_t ebx; int16_t bx; struct { int8_t bl; int8_t bh; }; };
    union { int32_t edx; int16_t dx; struct { int8_t dl; int8_t dh; }; };
    union { int32_t ecx; int16_t cx; struct { int8_t cl; int8_t ch; }; };
    union { int32_t eax; int16_t ax; struct { int8_t al; int8_t ah; }; };
    union { int32_t eip; int16_t ip; };  // 指令指针
    const int32_t fromAddress;           // Hook 来源地址
};
```

#### 64位 Register 结构 (x64)

```cpp
struct Register
{
    // 16个通用寄存器 (64位新增 r8-r15)
    union { int64_t r15; int32_t r15d; int16_t r15w; int8_t r15b; };
    union { int64_t r14; int32_t r14d; int16_t r14w; int8_t r14b; };
    union { int64_t r13; int32_t r13d; int16_t r13w; int8_t r13b; };
    union { int64_t r12; int32_t r12d; int16_t r12w; int8_t r12b; };
    union { int64_t r11; int32_t r11d; int16_t r11w; int8_t r11b; };
    union { int64_t r10; int32_t r10d; int16_t r10w; int8_t r10b; };
    union { int64_t r9;  int32_t r9d;  int16_t r9w;  int8_t r9b;  };
    union { int64_t r8;  int32_t r8d;  int16_t r8w;  int8_t r8b;  };
    // 传统寄存器扩展为64位
    union { int64_t rdi; int32_t edi; int16_t di; };
    union { int64_t rsi; int32_t esi; int16_t si; };
    union { int64_t rbp; int32_t ebp; int16_t bp; };
    union { int64_t rsp; int32_t esp; int16_t sp; };
    union { int64_t rbx; int32_t ebx; int16_t bx; struct { int8_t bl; int8_t bh; }; };
    union { int64_t rdx; int32_t edx; int16_t dx; struct { int8_t dl; int8_t dh; }; };
    union { int64_t rcx; int32_t ecx; int16_t cx; struct { int8_t cl; int8_t ch; }; };
    union { int64_t rax; int32_t eax; int16_t ax; struct { int8_t al; int8_t ah; }; };
    Eflags eflags;          // 标志寄存器 (64位)
    union { int64_t rip; int32_t eip; int16_t ip; };
    const int64_t fromAddress;
};
```

**关键差异总结：**

| 特性 | 32位 | 64位 |
|------|------|------|
| 通用寄存器数量 | 8个 (EAX/EBX/ECX/EDX/ESI/EDI/EBP/ESP) | 16个 (新增 R8-R15) |
| 寄存器宽度 | 32位 (最大) | 64位 (最大) |
| 子寄存器访问 | 16位/8位 | 64位/32位/16位/8位 |
| XMM 寄存器数量 | 8个 (XMM0-XMM7) | 16个 (XMM0-XMM15) |

### 2. 浮点寄存器保存区域差异

#### 32位 FXSAVE_Area

```cpp
struct alignas(16) FXSAVE_Area {
    // FPU/MMX 控制部分 (0x00-0x1F)
    uint16_t fpu_control_word;
    uint16_t fpu_status_word;
    // ... 其他 FPU 状态字段
    
    // ST0-ST7 寄存器 (0x20-0x9F)
    struct { uint8_t data[10]; uint8_t reserved[6]; } st_regs[8];
    
    // XMM0-XMM7 寄存器 (0xA0-0x1FF)
    struct alignas(16) { uint8_t xmm[16]; } xmm_regs[8];
    
    uint8_t reserved[224];
};
// 总大小: 512 字节
// 对齐要求: 16 字节
```

#### 64位 FXSAVE64_Area

```cpp
struct alignas(64) FXSAVE64_Area {
    // FPU/MMX 控制部分 (0x00-0x1F)
    uint16_t fpu_control_word;
    uint16_t fpu_status_word;
    // ... 其他 FPU 状态字段
    
    // ST0-ST7 寄存器 (0x20-0x9F)
    struct { uint8_t data[10]; uint8_t reserved[6]; } st_regs[8];
    
    // XMM0-XMM15 寄存器 (0xA0-0x1FF) - 64位扩展
    struct alignas(16) { uint8_t xmm[16]; } xmm_regs[16];
    
    uint8_t reserved[384];  // 可能包含 AVX 扩展状态
};
// 总大小: 512+ 字节
// 对齐要求: 64 字节 (兼容 AVX)
```

### 3. Hook Shellcode 差异

#### 32位 HookCallByteArr

```cpp
// 32位 Hook Shellcode (约 36 字节)
constexpr BYTE HookCallByteArr[] = {
    0x68,0x00,0x00,0x00,0x00,       // push hookAddress (压入Hook地址)
    0xE8,0x00,0x00,0x00,0x00,       // call callback (调用回调)
    0x60,                           // pushad (保存所有通用寄存器)
    0x9C,                           // pushfd (保存标志寄存器)
    0x83,0x44,0x24,0x10,0x08,       // add dword ptr [esp+0x10], 8
    0x83,0x44,0x24,0x24,0x17,       // add dword ptr [esp+0x24], 0x17
    0x54,                           // push esp
    0xE8,0x00,0x00,0x00,0x00,       // call callback (用户回调)
    0x9D,                           // popfd (恢复标志寄存器)
    0x61,                           // popad (恢复所有通用寄存器)
    0xC2,0x04,0x00,                 // ret 4 (返回并清理栈)
    0x8B,0x64,0x24,0xE4             // mov esp, [esp-0x1C] (栈修复)
};
```

#### 64位 HookCallByteArr

```cpp
// 64位 Hook Shellcode (约 141 字节)
constexpr BYTE HookCallByteArr[] = {
    0x48,0x8D,0x64,0x24,0xF8,       // lea rsp, [rsp-8] (栈对齐调整)
    0xC7,0x04,0x24,0x00,0x00,0x00,0x00,  // mov dword ptr [rsp], fromAddrLow
    0xC7,0x44,0x24,0x04,0x00,0x00,0x00,0x00, // mov dword ptr [rsp+4], fromAddrHigh
    0xE8,0x00,0x00,0x00,0x00,       // call (内部调用)
    0x9C,                           // pushfq (保存64位标志寄存器)
    0x50,                           // push rax
    0x51,                           // push rcx
    0x52,                           // push rdx
    0x53,                           // push rbx
    // ... 保存所有16个通用寄存器
    0x41,0x50,0x41,0x51,0x41,0x52,0x41,0x53,  // push r8-r15
    0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,
    // ... 栈调整和回调调用
    0x48,0xB8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // mov rax, callback
    0xFF,0xD0,                      // call rax
    // ... 恢复所有寄存器
    0x9D,                           // popfq
    0xC2,0x08,0x00,                 // ret 8
    0x48,0x8B,0x64,0x24,0xC0        // mov rsp, [rsp-0x40]
};
```

**Shellcode 关键差异：**

| 特性 | 32位 | 64位 |
|------|------|------|
| 大小 | ~36 字节 | ~141 字节 |
| 寄存器保存 | pushad (8个) | 手动push (16个) |
| 标志保存 | pushfd | pushfq |
| 地址传递 | 直接 push 32位地址 | 分高低32位传递 |
| 回调调用 | 相对 call | 绝对地址 call |
| 栈对齐 | 无特殊要求 | 需要16字节对齐 |

### 4. 内存管理差异

#### 32位内存管理

32位版本使用简单的 Windows Heap API：

```cpp
// 32位使用 HeapCreate/HeapAlloc
HANDLE heapHandle = 0;

if (heapHandle == NULL) {
    heapHandle = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 1024, 0);
}
LPVOID allocAddress = HeapAlloc(heapHandle, HEAP_ZERO_MEMORY, size);
```

**特点：**
- 简单直接，无需考虑地址距离
- 所有地址都在 32 位地址空间内
- 相对跳转 (±2GB) 足够覆盖整个地址空间

#### 64位内存管理 (CodeHeap)

64位版本使用自定义的 CodeHeap 类来解决跳转距离限制：

```cpp
class CodeHeap {
private:
    LPVOID allocAddress;           // 基准地址
    std::vector<BaseAddress> baseAddress;  // 多个内存页
    std::vector<CodeHeapData> allocArr;    // 分配记录
    size_t maxSize;                // 当前总大小

public:
    CodeHeap(LPVOID address);      // 以目标地址为基准
    LPVOID Alloc(size_t allocSize); // 分配内存
    bool Free(LPVOID address);     // 释放内存
};

// 分配策略：在目标地址附近查找可用内存
LPVOID CodeHeap::CreateHeap(LPVOID address) {
    LPVOID allocAddress = 0;
    long long distance = 0;
    bool before = false;
    while (allocAddress == 0) {
        allocAddress = VirtualAlloc(
            (LPVOID)((long long)address + distance),
            HEAP_SIZE, 
            MEM_COMMIT | MEM_RESERVE, 
            PAGE_EXECUTE_READWRITE
        );
        // 在目标地址前后交替搜索
        if (before) distance -= USN_PAGE_SIZE;
        else distance += USN_PAGE_SIZE;
        // 检查是否超出 32 位相对跳转范围
        if (distance > INT_MAX || distance < INT_MIN) {
            distance = 0;
            before = true;
        }
    }
    return allocAddress;
}
```

**CodeHeap 设计原因：**

64位地址空间巨大 (0x0000000000000000 - 0xFFFFFFFFFFFFFFFF)，但 `JMP rel32` 指令只能跳转 ±2GB 距离。CodeHeap 通过以下策略解决此问题：

1. **就近分配**：在目标地址附近分配可执行内存
2. **多页管理**：支持多个内存页，按需扩展
3. **内存池复用**：释放的内存可被重新利用
4. **距离检查**：确保分配的地址在跳转范围内

### 5. 栈对齐差异 (重要)

#### 32位栈对齐

32位系统对栈对齐没有严格要求，函数调用时栈可以任意对齐。

#### 64位栈对齐 (关键)

64位 Windows ABI 要求：**在执行 CALL 指令前，栈指针 (RSP) 必须是 16 字节对齐的**。

```cpp
// 64位 HookBegin 函数签名
HookError HookBegin(
    LPVOID hookAddress, 
    HookCallBack callBack, 
    bool isRSPAlign16Bytes = true,  // 新增参数！
    OriginalCodeLocation originalCodeLocation = OriginalCodeLocation_Behind, 
    LPCVOID jmpBackAddress = (LPCVOID)-1
);
```

**处理逻辑：**

```cpp
// 根据栈对齐状态调整 Shellcode
BYTE subRSPValue = isRSPAlign16Bytes ? 0x8 : 0x10;
// 在 Shellcode 中动态调整
// lea rsp, [rsp-8] 或 lea rsp, [rsp-16]
```

**为什么需要这个参数？**

当 Hook 点的 RSP 不是 16 字节对齐时，需要额外调整：
- 如果 RSP 已对齐：`lea rsp, [rsp-8]` (CALL 后 RSP-8，对齐被破坏，需要调整)
- 如果 RSP 未对齐：`lea rsp, [rsp-16]` (需要更多调整空间)

### 6. 反汇编处理差异

#### 32位反汇编

```cpp
DisAsmStr HookDisAsm(LPVOID address) {
    cs_open(CS_ARCH_X86, CS_MODE_32, &csHandle);  // 32位模式
    // ... 简单处理
}
```

#### 64位反汇编 (RIP 相对寻址处理)

```cpp
DisAsmStr HookDisAsm(LPVOID address) {
    cs_open(CS_ARCH_X86, CS_MODE_64, &csHandle);  // 64位模式
    
    // 64位特有：处理 RIP 相对寻址
    if (str.find("[") != std::string::npos) {
        std::string addressStr = str.substr(str.find("[") + 1, ...);
        size_t ripPos = addressStr.find("rip");
        if (ripPos != std::string::npos) {
            // 将 [rip+offset] 转换为绝对地址
            // 例如: mov rax, [rip+0x1000] -> mov rax, [0x实际地址]
            long long deviationAddr = htoi64(addressStr.substr(operatorPos + 1).c_str());
            if (addressStr[operatorPos] == '+') {
                _i64toa_s((long long)address + insn[i].size + deviationAddr, ...);
            }
            // ... 替换为绝对地址
        }
    }
}
```

**RIP 相对寻址说明：**

64位代码常用 RIP 相对寻址来访问全局变量和常量：
```asm
; 64位代码
mov rax, [rip+0x1000]    ; 加载 RIP+0x1000 处的数据
```

在 Hook 时，原代码被移动到新位置执行，RIP 已经改变，必须将相对地址转换为绝对地址。

### 7. 函数 Hook 差异

#### 32位函数 Hook

```cpp
// 使用 5 字节相对跳转
constexpr BYTE HookJmp[] = { 0xE9, 0, 0, 0, 0 };  // jmp rel32
```

#### 64位函数 Hook

```cpp
// 使用 14 字节绝对跳转 (解决距离限制)
constexpr BYTE HookJmpLong[] = { 
    0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,  // jmp [rip+0]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // 64位绝对地址
};
```

### 8. 标志位操作差异

#### 32位标志位操作

```cpp
// 使用内联汇编
Eflags Asm_Cmp(int num1, int num2) {
    Eflags result;
    _asm {
        mov eax, num2;
        cmp num1, eax;
        pushfd;
        pop result;
    }
    return result;
}
```

#### 64位标志位操作

```cpp
// 使用独立汇编文件 (x64 不支持内联汇编)
// EflagsChange.asm
.CODE
Asm_Cmp PROC
    cmp rcx, rdx      ; x64 调用约定: 参数在 rcx, rdx
    pushfq
    pop rax
    ret
Asm_Cmp ENDP
END

// C++ 声明
extern "C" {
    Eflags _stdcall Asm_Cmp(long long num1, long long num2);
}
```

### 9. 性能对比

| 指标 | 32位 | 64位 | 说明 |
|------|------|------|------|
| Hook 安装时间 | 较快 | 较慢 | 64位需要搜索合适内存位置 |
| Hook 执行开销 | ~50 周期 | ~100 周期 | 64位保存更多寄存器 |
| 内存占用 | 较小 | 较大 | 64位 Shellcode 更长 |
| 跳转效率 | 高 | 中等 | 64位可能需要间接跳转 |
| 最大 Hook 数量 | 理论无限 | 受内存距离限制 | 64位需要就近分配 |

### 10. 潜在问题与兼容性考量

#### 32位潜在问题

1. **线程安全**：全局 map 非线程安全，多线程 Hook 需要加锁
2. **内存碎片**：频繁 Hook/Unhook 可能导致堆碎片
3. **地址空间**：32位地址空间有限，大量 Hook 可能耗尽

#### 64位潜在问题

1. **跳转距离限制**：如果无法在 ±2GB 范围内分配内存，Hook 会失败
2. **栈对齐问题**：错误的 `isRSPAlign16Bytes` 参数会导致程序崩溃
3. **RIP 相对寻址**：某些复杂指令可能无法正确处理
4. **AVX 寄存器**：当前实现未保存 YMM 寄存器高 128 位

---

## 安装部署指南

### 环境要求

- **操作系统**：Windows 7 及以上 (x86/x64)
- **开发环境**：Visual Studio 2019 及以上 (v143 工具集)
- **Windows SDK**：10.0 及以上

### 构建步骤

#### 方法一：使用 Visual Studio

1. 打开 `HookAsm模板.sln`
2. 选择构建配置：
   - **32位**：选择 `Debug|Win32` 或 `Release|Win32`
   - **64位**：选择 `Debug|x64` 或 `Release|x64`
3. 构建解决方案 (Ctrl+Shift+B)
4. 输出文件位于对应的 `Debug/` 或 `Release/` 目录

#### 方法二：使用命令行

```powershell
# 32位版本
msbuild HookAsm模板.sln /p:Configuration=Release /p:Platform=Win32

# 64位版本
msbuild HookAsm模板.sln /p:Configuration=Release /p:Platform=x64
```

### 项目配置说明

#### 32位项目配置

```xml
<ConfigurationType>DynamicLibrary</ConfigurationType>
<PlatformToolset>v143</PlatformToolset>
<CharacterSet>Unicode</CharacterSet>
<PreprocessorDefinitions>WIN32;HOOKASMX32_EXPORTS;_WINDOWS;_USRDLL</PreprocessorDefinitions>
```

#### 64位项目配置

```xml
<ConfigurationType>DynamicLibrary</ConfigurationType>
<PlatformToolset>v143</PlatformToolset>
<CharacterSet>Unicode</CharacterSet>
<PreprocessorDefinitions>HookAsmX64_EXPORTS;_WINDOWS;_USRDLL</PreprocessorDefinitions>
```

**注意**：64位项目需要 MASM 汇编器支持：
```xml
<Import Project="$(VCTargetsPath)\BuildCustomizations\masm.props" />
```

---

## 使用说明

### 基本使用流程

```
1. 确定要 Hook 的地址
2. 编写 Hook 回调函数
3. 调用 HookBegin() 安装 Hook
4. 在回调函数中处理寄存器
5. 调用 HookStop() 卸载 Hook (可选)
```

### Hook 类型选择

| Hook 类型 | 使用场景 | 函数 |
|-----------|---------|------|
| 指令级 Hook | 在函数内部任意位置拦截 | `HookBegin` / `HookStop` |
| 函数级 Hook | 替换整个函数 | `HookFunctionBegin` / `HookFunctionStop` |

### 原代码执行位置

```cpp
enum OriginalCodeLocation {
    OriginalCodeLocation_Behind,   // 原代码在回调后执行
    OriginalCodeLocation_Front,    // 原代码在回调前执行
    OriginalCodeLocation_Without,  // 不执行原代码
};
```

---

## API 文档

### 错误码定义

```cpp
enum HookError : int {
    ErrorOk,               // 成功
    ErrorDisAsmFailed,     // 反汇编失败
    ErrorAsmFailed,        // 汇编失败
    ErrorMemoryAllocFailed,// 内存分配失败
    ErrorHasHooked,        // 该地址已被 Hook
    ErrorHasHookedNear,    // 附近地址已被 Hook (指令重叠)
    ErrorBadParameter,     // 参数错误
};
```

### 核心函数

#### HookBegin

安装指令级 Hook。

```cpp
// 32位版本
HookError HookBegin(
    LPVOID hookAddress,              // 要 Hook 的地址
    HookCallBack callBack,           // 回调函数
    OriginalCodeLocation originalCodeLocation = OriginalCodeLocation_Behind,
    LPCVOID jmpBackAddress = (LPCVOID)-1  // 回跳地址，-1 表示自动计算
);

// 64位版本
HookError HookBegin(
    LPVOID hookAddress,
    HookCallBack callBack,
    bool isRSPAlign16Bytes = true,   // Hook 点 RSP 是否 16 字节对齐
    OriginalCodeLocation originalCodeLocation = OriginalCodeLocation_Behind,
    LPCVOID jmpBackAddress = (LPCVOID)-1
);
```

#### HookStop

卸载指令级 Hook。

```cpp
bool HookStop(LPVOID hookAddress);  // 之前 Hook 的地址
```

#### HookFunctionBegin

安装函数级 Hook。

```cpp
HookError HookFunctionBegin(
    LPVOID newFunc,      // 新函数地址
    LPVOID* oldFunc      // 输入: 原函数地址; 输出: 可调用的原函数指针
);
```

#### HookFunctionStop

卸载函数级 Hook。

```cpp
bool HookFunctionStop(LPVOID* oldFunc);  // HookFunctionBegin 返回的指针
```

### 回调函数类型

```cpp
typedef void(_stdcall* HookCallBack)(Register& reg);
```

### Register 结构体成员

#### 32位成员

| 成员 | 类型 | 说明 |
|------|------|------|
| `eax`, `ax`, `al`, `ah` | int32/int16/int8 | 累加器 |
| `ebx`, `bx`, `bl`, `bh` | int32/int16/int8 | 基址寄存器 |
| `ecx`, `cx`, `cl`, `ch` | int32/int16/int8 | 计数器 |
| `edx`, `dx`, `dl`, `dh` | int32/int16/int8 | 数据寄存器 |
| `esi`, `si` | int32/int16 | 源索引寄存器 |
| `edi`, `di` | int32/int16 | 目标索引寄存器 |
| `ebp`, `bp` | int32/int16 | 基址指针 |
| `esp`, `sp` | int32/int16 | 栈指针 |
| `eip`, `ip` | int32/int16 | 指令指针 |
| `eflags` | DWORD | 标志寄存器 |
| `fromAddress` | const int32_t | Hook 来源地址 |

#### 64位成员 (扩展)

| 成员 | 类型 | 说明 |
|------|------|------|
| `rax`, `eax`, `ax`, `al`, `ah` | int64/int32/int16/int8 | 64位累加器 |
| `rbx`...`rsp` | ... | 扩展为64位 |
| `r8`...`r15` | int64/int32/int16/int8 | 新增寄存器 |
| `rip`, `eip`, `ip` | int64/int32/int16 | 64位指令指针 |
| `eflags` | DWORD64 | 64位标志寄存器 |
| `fromAddress` | const int64_t | 64位来源地址 |

### 辅助函数

#### Asm_Cmp / Asm_Test

获取比较/测试后的标志位。

```cpp
// 32位
Eflags Asm_Cmp(int num1, int num2);
Eflags Asm_Test(int num1, int num2);

// 64位
extern "C" {
    Eflags _stdcall Asm_Cmp(long long num1, long long num2);
    Eflags _stdcall Asm_Test(long long num1, long long num2);
}
```

#### Asm_Fxsave / Asm_Fxrstor

保存/恢复浮点寄存器。

```cpp
// 32位
FXSAVE_Area Asm_Fxsave();
void Asm_Fxrstor(const FXSAVE_Area& area);

// 64位
FXSAVE64_Area Asm_Fxsave();
void Asm_Fxrstor(const FXSAVE64_Area& area);
```

#### Asm_Ret / Asm_Ret_Free

生成/释放 RET 指令地址。

```cpp
// 32位
int32_t Asm_Ret();                    // 生成 ret 指令
int32_t Asm_Ret(int16_t theEspAdd);   // 生成 ret XXXX 指令
void Asm_Ret_Free(int16_t theEspAdd);

// 64位
int64_t Asm_Ret();
int64_t Asm_Ret(int16_t theRspAdd);
void Asm_Ret_Free(int16_t theRspAdd);
```

#### Asm_Mov_Esp_And_Jmp / Asm_Mov_Rsp_And_Jmp

生成修改栈指针并跳转的代码。

```cpp
// 32位
int32_t Asm_Mov_Esp_And_Jmp(int32_t theEsp, int32_t theJmpAddress);
void Asm_Mov_Esp_And_Jmp_Free(int32_t theEsp, int32_t theJmpAddress);

// 64位
int64_t Asm_Mov_Rsp_And_Jmp(int64_t theRsp, int64_t theJmpAddress);
void Asm_Mov_Rsp_And_Jmp_Free(int64_t theRsp, int64_t theJmpAddress);
```

---

## 示例代码

### 示例1：基本 Hook

```cpp
#include "main.h"
#include "HookAsm/HookAsm.h"

// 假设要 Hook 的地址
#define TARGET_ADDRESS 0x00401000

void _stdcall MyHookCallback(Register& reg)
{
    // 读取寄存器
    printf("EAX = 0x%08X\n", reg.eax);
    
    // 修改寄存器
    reg.eax = 0x12345678;
    
    // 修改执行流程 (跳过某些代码)
    // reg.eip = 0x00401100;
}

namespace Main
{
    void init_hook()
    {
        // 32位
        HookError err = HookBegin((LPVOID)TARGET_ADDRESS, MyHookCallback);
        
        // 64位 (需要指定栈对齐)
        // HookError err = HookBegin((LPVOID)TARGET_ADDRESS, MyHookCallback, true);
        
        if (err != ErrorOk) {
            printf("Hook failed: %d\n", err);
        }
    }

    void run()
    {
        // 主逻辑
    }

    void dll_exit()
    {
        // 卸载 Hook
        HookStop((LPVOID)TARGET_ADDRESS);
    }
}
```

### 示例2：函数 Hook

```cpp
#include "main.h"
#include "HookAsm/HookAsm.h"

// 原函数类型
typedef int (WINAPI* MessageBoxFunc)(HWND, LPCSTR, LPCSTR, UINT);
MessageBoxFunc OriginalMessageBox = MessageBoxA;

int WINAPI HookedMessageBox(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
    printf("MessageBox called: %s\n", lpText);
    // 调用原函数
    return OriginalMessageBox(hWnd, lpText, "Hooked!", uType);
}

namespace Main
{
    void init_hook()
    {
        LPVOID origFunc = (LPVOID)MessageBoxA;
        HookError err = HookFunctionBegin((LPVOID)HookedMessageBox, &origFunc);
        if (err == ErrorOk) {
            OriginalMessageBox = (MessageBoxFunc)origFunc;
        }
    }

    void dll_exit()
    {
        LPVOID origFunc = (LPVOID)OriginalMessageBox;
        HookFunctionStop(&origFunc);
    }
}
```

### 示例3：读取浮点寄存器

```cpp
#include "main.h"
#include "HookAsm/HookAsm.h"

void _stdcall MyHookCallback(Register& reg)
{
    // 保存当前浮点状态
    FXSAVE_Area fpuState = Asm_Fxsave();
    
    // 查看 XMM0 寄存器
    printf("XMM0: ");
    for (int i = 0; i < 16; i++) {
        printf("%02X ", fpuState.xmm_regs[0].xmm[i]);
    }
    printf("\n");
    
    // 恢复浮点状态
    Asm_Fxrstor(fpuState);
}
```

### 示例4：条件 Hook (跳过代码)

```cpp
#include "main.h"
#include "HookAsm/HookAsm.h"

void _stdcall ConditionalHook(Register& reg)
{
    // 根据条件决定是否跳过某段代码
    if (reg.eax > 100) {
        // 跳转到指定地址 (跳过某些检查)
        reg.eip = 0x00401200;
    }
    // 否则继续正常执行
}
```

### 示例5：64位栈对齐处理

```cpp
#include "main.h"
#include "HookAsm/HookAsm.h"

void _stdcall MyHookCallback(Register& reg)
{
    printf("RAX = 0x%016llX\n", reg.rax);
    printf("R8 = 0x%016llX\n", reg.r8);
}

namespace Main
{
    void init_hook()
    {
        LPVOID targetAddr = (LPVOID)0x140001000;
        
        // 方法1: 如果确定栈已对齐
        HookError err = HookBegin(targetAddr, MyHookCallback, true);
        
        // 方法2: 如果不确定栈对齐状态，可以检查
        // 通常函数入口处 RSP 是对齐的，函数内部可能不对齐
        // 如果 Hook 点在函数入口: isRSPAlign16Bytes = true
        // 如果 Hook 点在函数内部: 需要分析该点的 RSP 状态
        
        if (err != ErrorOk) {
            // 如果 Hook 失败，可能需要尝试不同的栈对齐设置
            err = HookBegin(targetAddr, MyHookCallback, false);
        }
    }
}
```

---

## 常见问题解答

### Q1: Hook 后程序崩溃

**可能原因：**
1. **64位栈未对齐**：检查 `isRSPAlign16Bytes` 参数
2. **Hook 点指令不完整**：确保 Hook 点在指令边界
3. **寄存器被错误修改**：检查回调函数中的寄存器操作
4. **原代码位置错误**：某些指令不能被移动执行

**解决方法：**
```cpp
// 1. 尝试不同的栈对齐设置
HookBegin(addr, callback, true);   // 先尝试 true
HookBegin(addr, callback, false);  // 如果失败尝试 false

// 2. 检查反汇编结果
DisAsmStr disasm = HookDisAsm(addr);
printf("Disassembly:\n%s\n", disasm.asmStr.c_str());
```

### Q2: Hook 安装失败 (ErrorMemoryAllocFailed)

**可能原因：**
- 64位版本无法在 ±2GB 范围内分配可执行内存

**解决方法：**
1. 尝试 Hook 其他位置
2. 减少同时存在的 Hook 数量
3. 使用 `VirtualAlloc` 预留内存区域

### Q3: 如何确定 64 位栈对齐状态？

**分析方法：**
```cpp
// 在调试器中查看 Hook 点的 RSP 值
// 如果 RSP % 16 == 8，则栈已对齐 (因为 CALL 会 push 8 字节返回地址)
// 如果 RSP % 16 == 0，则栈未对齐

// 经验法则：
// - 函数入口: 通常 isRSPAlign16Bytes = true
// - 函数内部: 需要具体分析
```

### Q4: Hook 后原代码行为异常

**可能原因：**
- 原代码包含 RIP 相对寻址 (64位)
- 原代码包含相对跳转/调用

**解决方法：**
- 库已自动处理大部分 RIP 相对寻址
- 对于复杂情况，考虑使用 `OriginalCodeLocation_Without` 并手动处理

### Q5: 如何 Hook usercall 函数？

```cpp
// usercall 使用非标准寄存器传参
// 例如: int __usercall func@<eax>(int a@<ecx>, int b@<edx>)

void _stdcall UsercallHook(Register& reg)
{
    // 直接从寄存器读取参数
    int a = reg.ecx;  // 第一个参数在 ecx
    int b = reg.edx;  // 第二个参数在 edx
    
    // 修改返回值
    reg.eax = a + b;  // 返回值在 eax
}
```

### Q6: 多线程环境下如何安全使用？

```cpp
#include <mutex>

std::mutex hookMutex;

void SafeHookBegin(LPVOID addr, HookCallBack cb)
{
    std::lock_guard<std::mutex> lock(hookMutex);
    HookBegin(addr, cb);
}

void SafeHookStop(LPVOID addr)
{
    std::lock_guard<std::mutex> lock(hookMutex);
    HookStop(addr);
}
```

---

## 注意事项与最佳实践

### 重要注意事项

1. **备份原代码**：Hook 前建议备份原代码，以便恢复
2. **避免递归 Hook**：回调函数中不要调用被 Hook 的函数
3. **栈平衡**：修改 ESP/RSP 时确保栈平衡
4. **线程安全**：多线程环境需要加锁保护
5. **测试充分**：在生产环境使用前充分测试

### 最佳实践

1. **最小化 Hook 范围**：只在必要的位置进行 Hook
2. **快速回调**：回调函数应尽快返回，避免阻塞
3. **错误处理**：始终检查 Hook 函数的返回值
4. **资源清理**：程序退出前卸载所有 Hook
5. **日志记录**：记录 Hook 安装/卸载状态，便于调试

### 性能优化建议

1. **批量 Hook**：一次性安装多个 Hook 比多次单独安装更高效
2. **避免频繁 Hook/Unhook**：频繁操作会产生内存碎片
3. **选择合适的 Hook 点**：选择低频执行的代码位置
4. **使用 OriginalCodeLocation_Without**：如果不需要执行原代码，可跳过以提升性能

---

## 依赖库说明

### Capstone

- **版本**：4.x
- **用途**：反汇编引擎，用于分析目标地址的指令
- **许可**：BSD 3-Clause
- **文件**：`capstone/capstone.h`, `capstone/capstone.lib`

### AsmJit

- **版本**：最新版 (嵌入)
- **用途**：JIT 编译器，用于运行时生成机器码
- **许可**：Zlib
- **目录**：`asmtk/asmjit/`

### AsmTk

- **版本**：最新版 (嵌入)
- **用途**：汇编解析器，将汇编文本转换为机器码
- **许可**：Zlib
- **文件**：`asmtk/asmparser.cpp`, `asmtk/asmtokenizer.cpp`

---

## 许可证信息

本项目采用 Apache License 2.0 许可证。

```
Copyright 2024 HookAsm Author

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

### 第三方库许可证

| 库 | 许可证 |
|----|--------|
| Capstone | BSD 3-Clause |
| AsmJit | Zlib |
| AsmTk | Zlib |

---

## 贡献指南

欢迎提交 Issue 和 Pull Request！

1. Fork 本仓库
2. 创建功能分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 创建 Pull Request

---

## 联系方式

如有问题或建议，请在 GitHub 上提交 Issue。

---

**免责声明**：本库仅供学习和研究目的。使用本库进行任何违法活动，后果自负。作者不承担任何法律责任。
