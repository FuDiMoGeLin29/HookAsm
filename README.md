# HookAsm

> 指令级 Hook 库 —— 在汇编代码的**任意指令边界**处进行 Hook，可读写通用寄存器、标志寄存器与浮点/SIMD 寄存器，支持 `usercall` 等非标准调用约定的 Hook。仅支持 Windows（x86 / x64）。

---

## 目录

- [版本与近期变更](#版本与近期变更)
- [项目概述](#项目概述)
- [功能特性](#功能特性)
- [技术架构](#技术架构)
- [核心模块详解](#核心模块详解)
- [32 位与 64 位实现差异](#32-位与-64-位实现差异)
- [安装部署指南](#安装部署指南)
- [使用说明](#使用说明)
- [API 文档](#api-文档)
- [示例代码](#示例代码)
- [常见问题解答](#常见问题解答)
- [注意事项与最佳实践](#注意事项与最佳实践)
- [依赖库说明](#依赖库说明)
- [许可证信息](#许可证信息)

---

## 版本与近期变更

本版本对底层引擎做了一次较大的替换与重构，升级前请先了解下面这些变化：

| 变更 | 说明 |
|------|------|
| **反汇编引擎替换** | 由 Capstone 更换为 **Zydis 5.0.0**（单文件 amalgamated 版本）。Zydis 负责指令解码、指令长度分析、分支目标与 x64 RIP 相对寻址的识别。 |
| **移除 AsmTk** | 删除了 `asmtk/` 目录（`asmparser.cpp` / `asmtokenizer.cpp`）。指令搬迁不再走“反汇编成文本 → 用汇编器把文本重新汇编”的路线。 |
| **新增指令重定位模块** | 新增 `HookRelocator`（x64）与 `HookRelocator32`（x86），直接对机器码做**等长重编码**与重定位，搬迁过程不再依赖文本汇编。 |
| **保留 AsmJit** | 仍使用 AsmJit 1.23.0 生成 Hook 跳板中“调用回调”的那段机器码（`CreateHookCallByteArr`）。原先写死的 `HookCallByteArr` 常量已废弃。 |
| **错误码调整** | 新增 `ErrorWriteMemoryFailed`；不再返回 `ErrorHasHooked` / `ErrorHasHookedNear`（已从枚举中移除）。 |
| **接口新增参数** | x64 `HookBegin` 新增 `isUseLongJump` 与 `minDisAsmSize`；x86 `HookBegin` 新增 `minDisAsmSize`；x64 `HookFunctionBegin` 新增 `isUseLongJump`。 |
| **移除公开反汇编 API** | 不再提供 `HookDisAsm` / `DisAsmStr`。需要查看某地址的指令时，可直接调用 `HookRelocator::Disassemble`。 |
| **工具集升级** | 工程使用 `v145` 工具集、C++20（`stdcpp20`）与 C17（`stdc17`）。 |

> 小提示：工程的预处理宏里仍保留 `ASMTK_STATIC`，属于历史残留（已无对应源码），可以安全删除。

---

## 项目概述

HookAsm 是一个指令级 Hook 库。与传统的函数级 Hook 不同，它可以在汇编代码的任意指令边界进行 Hook，因此能够：

- 在函数内部任意位置进行拦截
- 读写所有通用寄存器
- 读写标志寄存器（EFLAGS / RFLAGS）
- 读写浮点寄存器（FPU / XMM）
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

| 功能 | 32 位支持 | 64 位支持 | 说明 |
|------|:--------:|:--------:|------|
| 指令级 Hook | ✅ | ✅ | 在任意指令边界进行 Hook |
| 寄存器读写 | ✅ | ✅ | 读写 8 / 16 个通用寄存器 |
| 标志位读写 | ✅ | ✅ | EFLAGS / RFLAGS |
| FPU / XMM 寄存器 | ✅ | ✅ | 通过 `_fxsave` / `_fxrstor` 保存与恢复 |
| 函数级 Hook | ✅ | ✅ | 传统函数 Hook，可拿到“不递归”的原函数指针 |
| 原代码执行位置控制 | ✅ | ✅ | 前置 / 后置 / 不执行原代码 |
| 自定义回跳地址 | ✅ | ✅ | Hook 后跳转到指定地址 |
| 同一地址重复 Hook | ✅ | ✅ | 内部按栈结构记录，按后进先出卸载 |
| x64 长跳转模式 | — | ✅ | `isUseLongJump`，用 14 字节绝对跳转替代 ±2GB 相对跳转 |

### 高级特性

- **自动指令分析**：使用 Zydis 自动分析被 Hook 位置的指令，保证不会在指令中间截断，并识别分支目标与 RIP 相对寻址。
- **内置指令重定位**：`HookRelocator` 会把被搬走的指令重新编码到新地址，自动修正相对跳转 / 调用、`XBEGIN`、`LOOP` 家族以及 x64 RIP 相对内存操作数。
- **动态跳板生成**：使用 AsmJit 在运行期生成调用回调的跳板代码，因此跳板长度不再固定。
- **智能内存管理**：x64 使用 `CodeHeap` 在目标地址 ±2GB 范围内就近分配可执行内存，解决 `jmp rel32` 的距离限制。
- **可逆操作**：支持 Hook 的安装与卸载，恢复原始字节并归还内存。

---

## 技术架构

### 分层结构

~~~
┌───────────────────────────────────────────────────────────────┐
│                          用户代码层                            │
│   ┌────────────┐  ┌───────────────┐  ┌────────────────────┐   │
│   │ HookBegin  │  │ HookFunction  │  │ 辅助函数            │   │
│   │ HookStop   │  │ Begin / Stop  │  │ Asm_Ret / Fxsave …  │   │
│   └─────┬──────┘  └──────┬────────┘  └─────────┬──────────┘   │
└─────────┼────────────────┼─────────────────────┼──────────────┘
          │                │                     │
┌─────────┴────────────────┴─────────────────────┴──────────────┐
│                          核心引擎层                            │
│  ┌───────────────────────────┐   ┌─────────────────────────┐  │
│  │ 指令分析与重定位           │   │ 跳板代码生成             │  │
│  │ HookRelocator / 32        │   │ AsmJit 1.23.0           │  │
│  │   ├─ Zydis 解码            │   │ (CreateHookCallByteArr) │  │
│  │   └─ 等长重编码/重定位     │   └─────────────────────────┘  │
│  └───────────────────────────┘                                 │
└────────────────────────────────────────────────────────────────┘
          │
┌─────────┴──────────────────────────────────────────────────────┐
│                          内存管理层                             │
│   ┌─────────────────────┐      ┌──────────────────────────┐    │
│   │ 32 位：Heap API     │      │ 64 位：CodeHeap          │    │
│   │ (HEAP_CREATE_       │      │ (就近 VirtualAlloc 页池, │    │
│   │  ENABLE_EXECUTE)    │      │  ±2GB 搜索 + 内存复用)   │    │
│   └─────────────────────┘      └──────────────────────────┘    │
└────────────────────────────────────────────────────────────────┘
~~~

### `HookBegin` 的执行流程

1. `HookRelocator::Disassemble` 从目标地址开始解码，直到覆盖至少 `minDisAsmSize` 字节（默认取跳转指令自身长度，x86 为 5，x64 短跳转为 5 / 长跳转为 14）。
2. 生成一次跳板探针（dummy 地址），仅用于取得当前跳板的实际字节长度。
3. 分配可执行内存：x64 通过 `CodeHeap` 在目标地址附近分配并校验相对距离；x86 直接使用可执行堆。
4. `CreateHookCallByteArr` 生成调用回调的跳板代码。
5. `HookRelocator::RelocateTo` 把被“偷走”的指令重编码到跳板中，并返回重定位后的机器码。
6. 按 `originalCodeLocation` 决定 跳板 / 搬迁代码 / 回跳 的先后顺序，拼成完整跳板并写入内存。
7. 备份目标地址处的原始字节，然后写入跳转指令（x86 与 x64 短跳转写入 5 字节 `E9 rel32`，x64 长跳转写入 14 字节 `FF 25 00000000 + imm64`），剩余字节用多字节 NOP 填充。

### 目录结构

~~~
HookAsm模板/
├── HookAsm模板X32/                     # 32 位版本
│   ├── HookAsm/
│   │   ├── HookAsm.h                   # 对外头文件（API、Register、FXSAVE_Area）
│   │   ├── HookAsm.cpp                 # 对外 API 实现、跳板生成、Hook 生命周期
│   │   ├── HookRelocator32.h / .cpp    # 指令重定位（Zydis 解码 + 等长重编码）
│   │   ├── Zydis/                      # Zydis 5.0.0 单文件 amalgamated 版本
│   │   │   ├── Zydis.h
│   │   │   └── Zydis.c
│   │   └── asmjit/                     # AsmJit 1.23.0（仅用其 x86 汇编器）
│   ├── dllmain.cpp                     # DLL 入口（init_hook → 线程运行 run → dll_exit）
│   ├── main.cpp / main.h               # 用户代码模板
│   ├── framework.h                     # Windows 框架头
│   └── HookAsm模板X32.vcxproj
│
├── HookAsm模板X64/                     # 64 位版本
│   ├── HookAsm/
│   │   ├── HookAsm.h                   # 对外头文件（64 位 Register、FXSAVE64_Area）
│   │   ├── HookAsm.cpp                 # 对外 API 实现（含 CodeHeap 分配与长跳转）
│   │   ├── HookRelocator.h / .cpp      # 指令重定位（含 RIP 相对寻址修正）
│   │   ├── HookAsmCodeHeap.h / .cpp    # 就近可执行内存池
│   │   ├── EflagsChange.asm            # MASM：Asm_Cmp / Asm_Test（x64 无内联汇编）
│   │   ├── Zydis/                      # Zydis 5.0.0（同 32 位）
│   │   └── asmjit/                     # AsmJit 1.23.0
│   ├── dllmain.cpp
│   ├── main.cpp / main.h
│   ├── framework.h
│   └── HookAsm模板X64.vcxproj
│
├── HookAsm模板.sln                     # Visual Studio 解决方案
├── LICENSE.txt                         # Apache License 2.0
└── README.md                           # 本文档
~~~

---

## 核心模块详解

### 1. 指令分析：Zydis

- 头文件：`HookAsm/Zydis/Zydis.h`，实现：`HookAsm/Zydis/Zydis.c`（amalgamated 单文件，按 C17 编译，宏 `ZYDIS_STATIC_BUILD`）。
- 解码器初始化：
  - x64：`ZYDIS_MACHINE_MODE_LONG_64` / `ZYDIS_STACK_WIDTH_64`
  - x86：`ZYDIS_MACHINE_MODE_LEGACY_32` / `ZYDIS_STACK_WIDTH_32`
- 使用 `ZydisDecoderDecodeFull` 一次拿到指令与全部操作数，随后：
  - 通过 `meta.category`（`UNCOND_BR` / `COND_BR` / `CALL`）识别相对分支，取出相对立即数并计算绝对目标。
  - 识别 `XBEGIN`（隐式相对立即数）。
  - x64 额外识别内存操作数基址为 `RIP` 的 RIP 相对寻址。
  - 识别 `LOOP` / `LOOPE` / `LOOPNE` / `JCXZ` / `JECXZ`（x64 还有 `JRCXZ`）。

### 2. 指令重定位：`HookRelocator` / `HookRelocator32`

这是本次改造新增的核心模块，负责把“被 Hook 点覆盖的指令”安全地搬到跳板中执行。

~~~cpp
struct Instruction
{
    uint64_t address;       // 原始地址
    uint8_t  length;        // 原始长度
    uint64_t target;        // 分支/内存操作数的绝对目标（若适用）
    uint8_t  newLength;     // 重编码后的长度
    uint64_t newAddress;    // 搬迁后的地址

    bool isRelative;        // jmp / call / jcc
    bool isRipMem;          // x64：RIP 相对内存寻址
    bool isLoopFamily;      // loop / loope / loopne / jcxz / jecxz / jrcxz
    bool isXbegin;

    ZydisDecodedInstruction insn;
    ZydisDecodedOperand     operands[ZYDIS_MAX_OPERAND_COUNT];
};

struct DisasmResult { std::vector<Instruction> instructions; size_t totalBytes; size_t totalNewLength; };
struct RelocResult  { std::vector<uint8_t> bytes; size_t stolenBytes; size_t totalNewLength; };
~~~

| 接口 | 说明 |
|------|------|
| `std::optional<DisasmResult> Disassemble(uint64_t sourceAddr, size_t minBytes)` | 从 `sourceAddr` 开始解码，直到累计原始字节数 ≥ `minBytes`；解码失败返回 `nullopt`。 |
| `std::optional<RelocResult> RelocateTo(const std::vector<Instruction>&, uint64_t targetAddr)` | 把指令序列重编码到 `targetAddr`；任何一条指令无法等长编码都会返回 `nullopt`。 |

#### 搬迁策略

| 原始指令 | 处理方式 | 新长度 |
|----------|----------|--------|
| `jmp rel8 / rel32` | 重编码为 `E9 rel32` | 5 |
| `call rel32` | 重编码为 `E8 rel32` | 5 |
| `jcc rel8 / rel32` | 重编码为 `0F 8x rel32` | 6 |
| `xbegin` | 重编码为 `C7 F8 rel32` | 6 |
| `loop / loope / loopne` | 展开为 `pushf` / `dec` / `jz` / `popf` / `jmp` 等价序列 | 12 / 13 / 18 / 19 |
| `jcxz / jecxz / jrcxz` | 展开为 `pushf` / `test` / `jnz` / `popf` / `jmp` | 12 / 13 |
| x64 RIP 相对内存操作数 | 原样复制并修正 `disp32` | 不变 |
| 其他指令 | 原样复制字节 | 不变 |

#### LOOP 家族展开长度

| 指令 | x86（16 位计数器 `66` 前缀） | x86（32 位计数器） | x64（`ECX`） | x64（`RCX`） |
|------|:----:|:----:|:----:|:----:|
| `loop` | 13 | 12 | 12 | 13 |
| `loope / loopne` | 19 | 18 | 18 | 19 |
| `jcxz / jecxz / jrcxz` | 13 | 12 | 12 | 13 |

展开模板会依据解码出的 `address_width` 选择 16 位 / 32 位 / 64 位计数器形式，并在生成时把 `rel32` 精确回填到操作码之后。

#### 跳转目标重映射

`RelocateTo` 会先为每条指令计算新地址，然后对相对分支目标做一次映射：如果分支目标落在被搬迁的区间内部，就把它指向搬迁后的新地址；落在区间外部则保持原目标不变。

### 3. 跳板代码生成

`CreateHookCallByteArr` 使用 AsmJit 的 `CodeHolder` + `x86::Assembler` 在运行期生成跳板中“保存现场 → 调用回调 → 恢复现场”的部分：

- **x64**：先 `lea rsp,[rsp-8]` 并写入本次 Hook 的来源地址，然后依次 `pushfq` 与 16 个通用寄存器，在栈上直接构造出 `Register` 结构；`Register.rip` 复用 `call next` 压入的返回地址（被回调调用前的 `add dword ptr [rsp+0x88]` 修正），`fromAddress` 复用预先写入栈的两个 DWORD。回调返回后逐条弹栈，`ret 8` 跳过来源地址槽，最后 `mov rsp,[rsp-0x40]` 把回调对 `Register.rsp` 的修改真正应用回寄存器。因此：
  - `isRSPAlign16Bytes` 会决定 `sub rsp, 8` 还是 `sub rsp, 0x10`，从而保证调用回调前 RSP 满足 16 字节对齐。
  - 修改 `Register.rip` 与修改 `Register.rsp` **不能同时生效**（头文件已注明）。
- **x86**：使用 `push` 来源地址 + `pushad` + `pushfd` 保存现场，并修正栈上的 ESP / EIP 字段，最后 `ret 4` + `mov esp,[esp-0x1C]` 应用回调对 `Register.esp` 的修改。

### 4. 原代码位置与跳转方式

三种原代码位置模式决定跳板布局：

| 模式 | 跳板布局 |
|------|----------|
| `OriginalCodeLocation_Behind`（默认） | `[调用回调]` → `[搬迁的原指令]` → `[跳回]` |
| `OriginalCodeLocation_Front` | `[搬迁的原指令]` → `[调用回调]` → `[跳回]` |
| `OriginalCodeLocation_Without` | `[调用回调]` → `[跳回]`（不执行原指令） |

跳转方式：

| 场景 | Hook 点写入 | 跳板回跳 | 说明 |
|------|-------------|----------|------|
| x86 全部、x64 `isUseLongJump = false` | 5 字节 `E9 rel32` | 5 字节 `E9 rel32` | 依赖跳板与 Hook 点的距离在 ±2GB 内（由 `CodeHeap` 就近分配保证） |
| x64 `isUseLongJump = true` | 14 字节 `FF 25 00000000 + imm64` | 14 字节绝对跳转 | 不受距离限制，但会覆盖更多原指令字节 |

### 5. 内存管理

- **x86**：`HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, …)` + `HeapAlloc` / `HeapFree`。Hook 与函数 Hook 各用一个堆，最后一个分配被释放时销毁堆。
- **x64**：`CodeHeap`。以目标地址为中心，按页（`USN_PAGE_SIZE`，`VirtualAlloc` + `PAGE_EXECUTE_READWRITE`）向前 / 向后交替搜索可用区域，保证分配结果落在 `jmp rel32` 的 ±2GB 范围内；同一页内的分配按块记录，释放时清零并可被后续分配复用，页内分配全部释放后整页 `VirtualFree`。若无法在范围内分配则抛出 `CodeHeapException`，`HookBegin` 返回 `ErrorMemoryAllocFailed`。
- **辅助函数内存**：`Asm_Ret` / `Asm_Mov_Rsp_And_Jmp` 等在独立的可执行堆中按“参数组合”缓存，重复请求同一组合会复用同一块代码，`…_Free` 会清零并释放。

### 6. Hook 生命周期

`HookAsm.cpp` 内部使用 `map<LPVOID, stack<…>>` 记录 Hook 现场：

| 数据 | 含义 |
|------|------|
| `hookOriginalCodes / hookOriginalCodeSizes` | 备份的原始字节与长度 |
| `hookAllocAddresses` | 跳板所在的可执行内存地址 |
| `hookFuncAddresses / hookFuncOriginalCodes / hookFuncAllocAddresses` | 函数 Hook 的对应记录 |

由于使用栈（stack）保存，同一地址可以重复 Hook，并且必须按后进先出的顺序调用 `HookStop` 卸载。这些容器都是普通全局容器，**不保证线程安全**。

---

## 32 位与 64 位实现差异

### 1. 寄存器结构差异

#### 32 位 `Register`（x86）

~~~cpp
struct Register
{
    Eflags eflags;                                   // DWORD
    union { int32_t edi; int16_t di; };
    union { int32_t esi; int16_t si; };
    union { int32_t ebp; int16_t bp; };
    union { int32_t esp; int16_t sp; };
    union { int32_t ebx; int16_t bx; struct { int8_t bl, bh; }; };
    union { int32_t edx; int16_t dx; struct { int8_t dl, dh; }; };
    union { int32_t ecx; int16_t cx; struct { int8_t cl, ch; }; };
    union { int32_t eax; int16_t ax; struct { int8_t al, ah; }; };
    union { int32_t eip; int16_t ip; };               // 与 esp 修改互斥
    const int32_t fromAddress;
};
~~~

#### 64 位 `Register`（x64）

~~~cpp
struct Register
{
    union { int64_t r15; int32_t r15d; int16_t r15w; int8_t r15b; };
    // … r14 / r13 / r12 / r11 / r10 / r9 / r8 同理 …
    union { int64_t rdi; int32_t edi; int16_t di; int8_t dil; };
    union { int64_t rsi; int32_t esi; int16_t si; int8_t sil; };
    union { int64_t rbp; int32_t ebp; int16_t bp; int8_t bpl; };
    union { int64_t rsp; int32_t esp; int16_t sp; int8_t spl; };
    union { int64_t rbx; int32_t ebx; int16_t bx; struct { int8_t bl, bh; }; };
    union { int64_t rdx; int32_t edx; int16_t dx; struct { int8_t dl, dh; }; };
    union { int64_t rcx; int32_t ecx; int16_t cx; struct { int8_t cl, ch; }; };
    union { int64_t rax; int32_t eax; int16_t ax; struct { int8_t al, ah; }; };
    Eflags eflags;                                   // DWORD64
    union { int64_t rip; int32_t eip; int16_t ip; }; // 与 rsp 修改互斥
    const int64_t fromAddress;
};
~~~

**关键差异：**

| 特性 | 32 位 | 64 位 |
|------|-------|-------|
| 通用寄存器数量 | 8（EAX…ESP） | 16（新增 R8–R15） |
| 最大寄存器宽度 | 32 位 | 64 位 |
| 子寄存器访问 | 16 / 8 位 | 64 / 32 / 16 / 8 位（含 `dil/sil/bpl/spl`） |
| 标志寄存器类型 | `DWORD` | `DWORD64` |
| XMM 寄存器数量 | 8（XMM0–XMM7） | 16（XMM0–XMM15） |

### 2. 浮点寄存器保存区差异

~~~cpp
// x86：512 字节，16 字节对齐
struct alignas(16) FXSAVE_Area {
    uint16_t fpu_control_word, fpu_status_word, fpu_tag_word, fpu_opcode;
    uint32_t fpu_eip, fpu_cs, fpu_data_offset, fpu_data_selector;
    uint32_t fpu_mxcsr, fpu_mxcsr_mask;
    struct { uint8_t data[10]; uint8_t reserved[6]; } st_regs[8];   // ST0-ST7
    struct alignas(16) { uint8_t xmm[16]; } xmm_regs[8];            // XMM0-XMM7
    uint8_t reserved[224];
};

// x64：800 字节，64 字节对齐（兼容 AVX 对齐要求），XMM 扩展为 16 个
struct alignas(64) FXSAVE64_Area {
    /* 同上 FPU 头部 32 字节 */
    struct { uint8_t data[10]; uint8_t reserved[6]; } st_regs[8];
    struct alignas(16) { uint8_t xmm[16]; } xmm_regs[16];           // XMM0-XMM15
    uint8_t reserved[384];                                          // 预留给扩展状态
};
~~~

两个结构都通过 `static_assert(sizeof(...) >= 512)` 做编译期校验，并使用文件内全局的 `alignas` 缓冲区配合 `_fxsave` / `_fxrstor` 完成保存与恢复。

### 3. 跳板（stub）生成差异

| 特性 | 32 位 | 64 位 |
|------|-------|-------|
| 现场保存 | `pushad` + `pushfd` | 逐条 `push` 16 个通用寄存器 + `pushfq` |
| 回调调用 | 相对 `call` | `movabs rax, callback` + `call rax` |
| 来源地址传递 | `push` 32 位地址 | 分成低 / 高 32 位写入栈槽 |
| 栈对齐 | 无特殊要求 | 必须保证调用回调前 RSP 16 字节对齐 |
| 栈修改生效 | `mov esp,[esp-0x1C]` | `mov rsp,[rsp-0x40]` |
| 生成方式 | AsmJit 运行期生成 | AsmJit 运行期生成 |

### 4. 内存管理差异

#### 32 位

~~~cpp
HANDLE heapHandle = NULL;
if (heapHandle == NULL)
    heapHandle = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 1024, 0);
LPVOID allocAddress = HeapAlloc(heapHandle, HEAP_ZERO_MEMORY, size);
~~~

32 位地址空间只有 4GB，`jmp rel32` 的 ±2GB 范围足以覆盖需要跳转的目标，因此无需关心分配位置。

#### 64 位（`CodeHeap`）

~~~cpp
LPVOID CodeHeap::CreateHeap(LPVOID address)
{
    LPVOID allocAddress = 0;
    long long distance = 0;
    bool before = false;
    while (allocAddress == 0)
    {
        allocAddress = VirtualAlloc((LPVOID)((long long)address + distance),
            HEAP_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (before) {
            distance -= USN_PAGE_SIZE;
            if (distance < INT_MIN) return 0;          // 搜索失败
        } else {
            distance += USN_PAGE_SIZE;
            if (distance > INT_MAX) { distance = 0; before = true; continue; }
        }
    }
    return allocAddress;
}
~~~

设计要点：

1. **就近分配**：以目标地址为基准向两侧交替搜索，保证落在 `jmp rel32` 可达范围内。
2. **多页管理**：每页 `USN_PAGE_SIZE`，页内按分配块记录 `size / isFree / baseAddressId`。
3. **内存复用**：释放的块会被清零并标记为空闲，后续同尺寸请求可直接复用。
4. **整页回收**：当某页上的分配计数归零时 `VirtualFree` 整页，`maxSize` 同步减少；为 0 时 `HookBegin` 会销毁并移除该 `CodeHeap`。

### 5. 栈对齐差异（重要）

x64 Windows ABI 要求：**在执行 `CALL` 之前 RSP 必须 16 字节对齐**。

~~~cpp
// x64 HookBegin 签名（节选）
HookError HookBegin(
    LPVOID hookAddress,
    HookCallBack callBack,
    bool isRSPAlign16Bytes = true,   // Hook 点的 RSP 是否 16 字节对齐
    OriginalCodeLocation originalCodeLocation = OriginalCodeLocation_Behind,
    bool isUseLongJump = false,
    size_t minDisAsmSize = 0,
    LPCVOID jmpBackAddress = (LPCVOID)-1);
~~~

跳板中对应的处理：

~~~cpp
uint8_t subRSPValue = isRSPAlign16Bytes ? 0x8 : 0x10;
a.sub(x86::rsp, subRSPValue);
a.lea(x86::rcx, x86::ptr(x86::rsp, subRSPValue));   // Register& 参数
~~~

经验判断：

- 函数入口处（刚 `call` 进来）RSP ≡ 8 (mod 16)，此时通常传 `true`。
- 函数内部经过若干 `push` / `sub rsp` 后状态不确定，需要具体分析，传错会直接崩溃。

### 6. 指令搬迁差异

#### 32 位

32 位没有 RIP 相对寻址，绝大多数指令搬迁时可以直接复制字节，只有相对分支与 `LOOP` 家族需要重编码 / 展开：

~~~cpp
ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32);
~~~

#### 64 位（RIP 相对寻址处理）

64 位代码大量使用 RIP 相对寻址访问全局变量与常量：

~~~asm
mov rax, [rip+0x1000]     ; 读取 RIP+0x1000 处的数据
~~~

指令被搬到跳板后 RIP 已经改变，必须修正 `disp32`。`HookRelocator::RelocateTo` 中的 `EncodeRipMem` 会原样复制指令字节，然后按 `insn.raw.disp.offset` 精确定位位移字段并写入新的位移：

~~~cpp
uint64_t newNext = newAddr + info.length;
int64_t  newDisp = (int64_t)info.target - (int64_t)newNext;   // 修正后的 disp32
~~~

另外 x64 的 `LOOP` 家族会根据 `address_width` 选择 `ECX` 或 `RCX` 形式的展开模板（`JRCXZ` 使用 `test rcx,rcx`）。

### 7. 函数 Hook 差异

| 项目 | 32 位 | 64 位 |
|------|-------|-------|
| 长跳转参数 | 无 | `isUseLongJump` |
| 默认（`false`） | 原函数头写 5 字节 `E9 rel32` 指向跳板；跳板头部是 14 字节绝对跳转到新函数，随后是搬迁的原指令与回跳 | 同左 |
| `isUseLongJump = true` | — | 原函数头写 14 字节绝对跳转到新函数；跳板为“搬迁的原指令 + 14 字节绝对跳回” |
| `oldFunc` 返回值 | 跳板起始地址 | 短跳转模式下为“跳板 + 14”（即搬迁后的原指令入口）；长跳转模式下为跳板起始 |

无论哪种模式，`oldFunc` 返回的地址都可以安全调用而不会再次进入 Hook。

### 8. 标志位操作差异

~~~cpp
// x86：内联汇编
Eflags Asm_Cmp(int num1, int num2)
{
    Eflags result;
    _asm { mov eax, num2; cmp num1, eax; pushfd; pop result; }
    return result;
}

// x64：独立 MASM 文件 HookAsm/EflagsChange.asm
Asm_Cmp PROC
    cmp rcx,rdx
    pushfq
    pop rax
    ret
Asm_Cmp ENDP
~~~

### 9. 性能对比

| 指标 | 32 位 | 64 位 | 说明 |
|------|-------|-------|------|
| Hook 安装时间 | 较快 | 较慢 | x64 需要搜索合适的内存页 |
| Hook 执行开销 | 较低 | 较高 | x64 保存 16 个寄存器 + RFLAGS |
| 内存占用 | 较小 | 较大 | x64 跳板更长，且按页分配 |
| 跳转效率 | 高 | 高（短跳转模式） | 长跳转模式多一次间接跳转 |
| 最大 Hook 数量 | 受堆大小限制 | 受 ±2GB 范围内可分配页数限制 | |

### 10. 潜在问题与兼容性

**32 位：**

1. 全局容器非线程安全，多线程 Hook 需要自行加锁。
2. 频繁 Hook / Unhook 会造成堆碎片。
3. 32 位地址空间有限，大量 Hook 可能耗尽可用地址。

**64 位：**

1. 若无法在 ±2GB 内分配可执行内存，短跳转模式会返回 `ErrorMemoryAllocFailed`；此时可改用 `isUseLongJump = true`（代价是覆盖 14 字节原指令）。
2. `isRSPAlign16Bytes` 传错会导致回调内调用 API 时崩溃。
3. RIP 相对寻址已自动修正，但若搬迁距离导致 `rel32` 溢出，重定位会失败（返回 `ErrorAsmFailed`）。
4. 当前只保存 XMM，不保存 YMM/ZMM 的高位，AVX 场景需要自行处理。

---

## 安装部署指南

### 环境要求

| 项目 | 要求 |
|------|------|
| 操作系统 | Windows 7 及以上（x86 / x64） |
| 开发环境 | Visual Studio（带 **v145** 工具集） |
| Windows SDK | 10.0 及以上 |
| 语言标准 | C++20（`stdcpp20`）/ C17（`stdc17`） |
| 运行时库 | `MultiThreaded` / `MultiThreadedDebug`（静态 CRT） |
| 汇编器 | x64 需要 MASM（`EflagsChange.asm`）；x86 使用内联汇编 |

> 如果使用较旧的 Visual Studio，请把两个工程的 `PlatformToolset` 从 `v145` 改为你本机安装的工具集（例如 `v143`）。

### 构建步骤

#### 方法一：Visual Studio

1. 打开 `HookAsm模板.sln`。
2. 选择配置：
   - 32 位：`Debug|Win32` 或 `Release|Win32`
   - 64 位：`Debug|x64` 或 `Release|x64`
3. 生成解决方案（Ctrl+Shift+B）。

#### 方法二：命令行

~~~powershell
# 32 位
msbuild "HookAsm模板.sln" /p:Configuration=Release /p:Platform=Win32

# 64 位
msbuild "HookAsm模板.sln" /p:Configuration=Release /p:Platform=x64
~~~

### 输出文件

| 配置 | 输出 |
|------|------|
| `Debug\|Win32` | `Debug\HookAsm模板X32.dll`（含 `.pdb` / `.lib` / `.exp`） |
| `Release\|Win32` | `Release\HookAsm模板X32.dll` |
| `Debug\|x64` | `x64\Debug\HookAsm模板X64.dll` |
| `Release\|x64` | `x64\Release\HookAsm模板X64.dll` |

### 项目配置说明

~~~xml
<!-- 公共部分 -->
<ConfigurationType>DynamicLibrary</ConfigurationType>
<PlatformToolset>v145</PlatformToolset>
<LanguageStandard>stdcpp20</LanguageStandard>
<LanguageStandard_C>stdc17</LanguageStandard_C>

<!-- x86 -->
<PreprocessorDefinitions>WIN32;HOOKASMX32_EXPORTS;_WINDOWS;_USRDLL;ASMTK_STATIC;ASMJIT_STATIC;ZYDIS_STATIC_BUILD</PreprocessorDefinitions>

<!-- x64（额外需要 MASM 支持） -->
<PreprocessorDefinitions>HookAsmX64_EXPORTS;_WINDOWS;_USRDLL;ASMTK_STATIC;ASMJIT_STATIC;ZYDIS_STATIC_BUILD</PreprocessorDefinitions>
<Import Project="$(VCTargetsPath)\BuildCustomizations\masm.props" />
~~~

需要注意：

- `ZYDIS_STATIC_BUILD` 用于把 amalgamated 的 `Zydis.c` 编译为静态库形式。
- `ASMJIT_STATIC` 用于静态链接 AsmJit。
- `ASMTK_STATIC` 已经没有对应代码，属于历史残留。
- 两个工程目前仍把 AsmJit 自带的 `*_test.cpp`（axl / core / x86 / arm 测试源文件）加入编译。它们只增加编译时间，不影响功能，可按需从工程中移除。

---

## 使用说明

### 基本流程

~~~
1. 确定要 Hook 的地址（指令边界）
2. 编写 Hook 回调函数
3. 调用 HookBegin() 安装 Hook
4. 在回调中读取 / 修改寄存器
5. 需要时调用 HookStop() 卸载 Hook
~~~

### Hook 类型选择

| 类型 | 使用场景 | 函数 |
|------|----------|------|
| 指令级 Hook | 在函数内部任意指令边界拦截 | `HookBegin` / `HookStop` |
| 函数级 Hook | 替换整个函数 | `HookFunctionBegin` / `HookFunctionStop` |

### 原代码执行位置

~~~cpp
enum OriginalCodeLocation : int
{
    OriginalCodeLocation_Behind,   // 回调执行完再执行原指令（默认）
    OriginalCodeLocation_Front,    // 先执行原指令再进入回调
    OriginalCodeLocation_Without,  // 不执行原指令
};
~~~

### 参数速查

| 参数 | 适用 | 说明 |
|------|------|------|
| `isRSPAlign16Bytes` | x64 | Hook 点处 RSP 是否 16 字节对齐，默认 `true` |
| `originalCodeLocation` | 全部 | 原指令执行时机 |
| `isUseLongJump` | x64 | 使用 14 字节绝对跳转替代 5 字节相对跳转，默认 `false` |
| `minDisAsmSize` | 全部 | 至少反汇编 / 搬迁的字节数。默认 0，表示恰好覆盖跳转指令所需长度；填入小于跳转长度的值会被提升为跳转长度 |
| `jmpBackAddress` | 全部 | 自定义回跳地址，默认 `(LPCVOID)-1`（自动回到 Hook 点之后） |

---

## API 文档

### 错误码

~~~cpp
enum HookError : int
{
    ErrorOk,                 // 成功
    ErrorDisAsmFailed,       // 反汇编失败（Zydis 解码失败或参数无效）
    ErrorAsmFailed,          // 指令重定位 / 编码失败
    ErrorMemoryAllocFailed,  // 可执行内存分配失败
    ErrorBadParameter,       // 参数错误（如 originalCodeLocation 非法）
    ErrorWriteMemoryFailed,  // 写入目标代码或跳板失败
};
~~~

> `ErrorHasHooked` / `ErrorHasHookedNear` 已从枚举中移除；同一地址重复 Hook 现在是允许的，按栈结构记录。

### 核心函数

#### `HookBegin` —— 安装指令级 Hook

~~~cpp
// x86
HookError HookBegin(
    LPVOID hookAddress,
    HookCallBack callBack,
    OriginalCodeLocation originalCodeLocation = OriginalCodeLocation_Behind,
    size_t minDisAsmSize = 0,
    LPCVOID jmpBackAddress = (LPCVOID)-1);

// x64
HookError HookBegin(
    LPVOID hookAddress,
    HookCallBack callBack,
    bool isRSPAlign16Bytes = true,
    OriginalCodeLocation originalCodeLocation = OriginalCodeLocation_Behind,
    bool isUseLongJump = false,
    size_t minDisAsmSize = 0,
    LPCVOID jmpBackAddress = (LPCVOID)-1);
~~~

#### `HookStop` —— 卸载指令级 Hook

~~~cpp
bool HookStop(LPVOID hookAddress);   // 传入之前 Hook 的地址
~~~

#### `HookFunctionBegin` —— 安装函数级 Hook

~~~cpp
// x86
HookError HookFunctionBegin(LPVOID newFunc, LPVOID* oldFunc);

// x64
HookError HookFunctionBegin(LPVOID newFunc, LPVOID* oldFunc, bool isUseLongJump = false);
~~~

- `oldFunc`：输入原函数地址，输出“可安全调用且不会递归”的指针。

#### `HookFunctionStop` —— 卸载函数级 Hook

~~~cpp
bool HookFunctionStop(LPVOID* oldFunc);   // 传入 HookFunctionBegin 输出的指针
~~~

### 回调类型

~~~cpp
typedef void(_stdcall* HookCallBack)(Register& reg);
~~~

### `Register` 结构体成员

#### 32 位

| 成员 | 类型 | 说明 |
|------|------|------|
| `eax / ax / al / ah` | int32 / int16 / int8 | 累加器 |
| `ebx / bx / bl / bh` | int32 / int16 / int8 | 基址寄存器 |
| `ecx / cx / cl / ch` | int32 / int16 / int8 | 计数器 |
| `edx / dx / dl / dh` | int32 / int16 / int8 | 数据寄存器 |
| `esi / si`、`edi / di` | int32 / int16 | 索引寄存器 |
| `ebp / bp`、`esp / sp` | int32 / int16 | 帧指针 / 栈指针 |
| `eip / ip` | int32 / int16 | 指令指针（与 `esp` 修改互斥） |
| `eflags` | DWORD | 标志寄存器 |
| `fromAddress` | const int32_t | Hook 来源地址 |

#### 64 位（扩展）

| 成员 | 类型 | 说明 |
|------|------|------|
| `rax / eax / ax / al / ah` 等 | int64 / int32 / int16 / int8 | 16 个通用寄存器都支持 64/32/16/8 位别名 |
| `rdi / rsi / rbp / rsp / rbx / rdx / rcx / rax` | int64 | 传统寄存器的 64 位形式（`dil/sil/bpl/spl` 也受支持） |
| `r8 – r15` | int64 / int32 / int16 / int8 | 新增寄存器 |
| `rip / eip / ip` | int64 / int32 / int16 | 指令指针（与 `rsp` 修改互斥） |
| `eflags` | DWORD64 | 64 位标志寄存器 |
| `fromAddress` | const int64_t | Hook 来源地址 |

### 辅助函数

#### 标志位

~~~cpp
// x86：内联汇编实现
Eflags Asm_Cmp(int num1, int num2);
Eflags Asm_Test(int num1, int num2);

// x64：MASM 实现（rcx / rdx 传参）
extern "C" {
    Eflags _stdcall Asm_Cmp(long long num1, long long num2);
    Eflags _stdcall Asm_Test(long long num1, long long num2);
}
~~~

#### 浮点 / SIMD 寄存器

~~~cpp
// x86
FXSAVE_Area   Asm_Fxsave();
void          Asm_Fxrstor(const FXSAVE_Area& area);

// x64
FXSAVE64_Area Asm_Fxsave();
void          Asm_Fxrstor(const FXSAVE64_Area& area);
~~~

#### 生成 `ret` / `ret imm`

~~~cpp
// x86
int32_t Asm_Ret();
int32_t Asm_Ret(int16_t theEspAdd);
void    Asm_Ret_Free(int16_t theEspAdd);

// x64
int64_t Asm_Ret();
int64_t Asm_Ret(int16_t theRspAdd);
void    Asm_Ret_Free(int16_t theRspAdd);
~~~

#### 生成“修改栈指针并跳转”

~~~cpp
// x86
int32_t Asm_Mov_Esp_And_Jmp(int32_t theEsp, int32_t theJmpAddress);
void    Asm_Mov_Esp_And_Jmp_Free(int32_t theEsp, int32_t theJmpAddress);

// x64
int64_t Asm_Mov_Rsp_And_Jmp(int64_t theRsp, int64_t theJmpAddress);
void    Asm_Mov_Rsp_And_Jmp_Free(int64_t theRsp, int64_t theJmpAddress);
~~~

#### 反汇编查询（可选）

旧版的 `HookDisAsm` 已移除。需要查看指令时可以直接使用重定位模块：

~~~cpp
HookAsm::HookRelocator reloc;
auto res = reloc.Disassemble((uint64_t)address, 5);
if (res) {
    printf("bytes=%zu, newLength=%zu, insns=%zu\n",
        res->totalBytes, res->totalNewLength, res->instructions.size());
}
~~~

> `htoi`（x86）/ `htoi64`（x64）是遗留的“十六进制字符串转整数”辅助函数，当前实现内部已不再依赖。

---

## 示例代码

### 示例 1：基本 Hook

~~~cpp
#include "main.h"
#include "HookAsm/HookAsm.h"

#define TARGET_ADDRESS 0x00401000

void _stdcall MyHookCallback(Register& reg)
{
    printf("EAX = 0x%08X, from = %p\n", reg.eax, (void*)reg.fromAddress);

    reg.eax = 0x12345678;      // 修改寄存器
    // reg.eip = 0x00401100;   // 修改执行流程（会跳离原路径）
}

namespace Main
{
    void init_hook()
    {
        // x86
        HookError err = HookBegin((LPVOID)TARGET_ADDRESS, MyHookCallback);

        // x64（需要指定栈对齐）
        // HookError err = HookBegin((LPVOID)TARGET_ADDRESS, MyHookCallback, true);

        if (err != ErrorOk)
            printf("Hook failed: %d\n", err);
    }

    void run() { /* 主逻辑 */ }

    void dll_exit()
    {
        HookStop((LPVOID)TARGET_ADDRESS);
    }
}
~~~

### 示例 2：函数 Hook

~~~cpp
#include "main.h"
#include "HookAsm/HookAsm.h"

typedef int (WINAPI* MessageBoxFunc)(HWND, LPCSTR, LPCSTR, UINT);
MessageBoxFunc OriginalMessageBox = MessageBoxA;

int WINAPI HookedMessageBox(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
    printf("MessageBox called: %s\n", lpText);
    return OriginalMessageBox(hWnd, lpText, "Hooked!", uType);   // 调用原函数
}

namespace Main
{
    void init_hook()
    {
        LPVOID origFunc = (LPVOID)MessageBoxA;
        HookError err = HookFunctionBegin((LPVOID)HookedMessageBox, &origFunc);
        if (err == ErrorOk)
            OriginalMessageBox = (MessageBoxFunc)origFunc;
    }

    void dll_exit()
    {
        LPVOID origFunc = (LPVOID)OriginalMessageBox;
        HookFunctionStop(&origFunc);
    }
}
~~~

### 示例 3：读取 XMM 寄存器

~~~cpp
void _stdcall MyHookCallback(Register& reg)
{
    FXSAVE64_Area fpu = Asm_Fxsave();      // x86 使用 FXSAVE_Area

    printf("XMM0: ");
    for (int i = 0; i < 16; ++i)
        printf("%02X ", fpu.xmm_regs[0].xmm[i]);
    printf("\n");

    Asm_Fxrstor(fpu);                      // 恢复现场，避免影响被测程序
}
~~~

### 示例 4：条件 Hook / 跳过检查

~~~cpp
void _stdcall ConditionalHook(Register& reg)
{
    if (reg.eax > 100)
        reg.eip = 0x00401200;   // 直接跳转，跳过后续检查代码
    // 否则继续正常执行
}
~~~

### 示例 5：usercall Hook

~~~cpp
// 例如：int __usercall func@<eax>(int a@<ecx>, int b@<edx>)
void _stdcall UsercallHook(Register& reg)
{
    int a = reg.ecx;        // 第一个参数
    int b = reg.edx;        // 第二个参数
    reg.eax = a + b;        // 返回值放回 eax
}
~~~

### 示例 6：x64 栈对齐与长跳转

~~~cpp
namespace Main
{
    void init_hook()
    {
        LPVOID targetAddr = (LPVOID)0x140001000;

        // 常规：5 字节相对跳转 + 就近分配跳板
        HookError err = HookBegin(targetAddr, MyHookCallback, /*isRSPAlign16Bytes=*/true);

        // 如果短跳转失败（例如无法在 ±2GB 内分配内存），改用长跳转：
        // err = HookBegin(targetAddr, MyHookCallback, true,
        //                 OriginalCodeLocation_Behind, /*isUseLongJump=*/true);
    }
}
~~~

### 示例 7：加大最小搬迁长度

~~~cpp
// 至少搬迁 16 字节（会解码到覆盖 16 字节的完整指令为止）
HookBegin(address, callback, true, OriginalCodeLocation_Behind, false, 16);
~~~

---

## 常见问题解答

### Q1：Hook 后程序崩溃

可能原因：

1. **x64 栈未 16 字节对齐** —— 检查 `isRSPAlign16Bytes`。
2. **Hook 点不在指令边界** —— 反汇编会从给定地址开始解码，请确认地址是指令起始位置。
3. **回调修改了栈 / 指令指针** —— `Register.rip` 与 `Register.rsp` 不能同时修改。
4. **回调里做了重操作** —— 回调在目标线程上下文中执行，长时间阻塞或调用被 Hook 的函数都可能出问题。

### Q2：返回 `ErrorMemoryAllocFailed`

- x64：`CodeHeap` 无法在 ±2GB 范围内分配页。可尝试：
  1. 改用 `isUseLongJump = true`；
  2. 减少同时存在的 Hook 数量；
  3. 在其他位置 Hook。
- x86：可执行堆创建失败，通常是地址空间耗尽或堆句柄创建失败。

### Q3：返回 `ErrorAsmFailed`

表示指令搬迁失败，常见于：

- 相对分支重编码后 `rel32` 溢出（跳板离原目标太远）；
- 出现无法等长重编码的指令；
- `LOOP` 家族展开模板长度与预期不符。

处理方式：尝试改变 Hook 位置（让跳板可以更接近目标）、调整 `minDisAsmSize`，或对这段代码改用 `OriginalCodeLocation_Without` 并自行实现等价逻辑。

### Q4：如何判断 x64 Hook 点的栈对齐状态？

- 函数入口（刚被 `call` 进入）：RSP ≡ 8 (mod 16) → `isRSPAlign16Bytes = true`。
- 函数内部：取决于该点之前的 `push` / `sub rsp` 情况，必须在调试器中实际查看 RSP。
- 不确定时可以先试 `true`，崩溃再试 `false`。

### Q5：Hook 后原指令行为异常

现在这些情况会由 `HookRelocator` 自动处理：

- 相对 `jmp / call / jcc` → 重编码；
- `XBEGIN` → 重编码；
- `LOOP / LOOPE / LOOPNE / JCXZ / JECXZ / JRCXZ` → 展开；
- x64 RIP 相对内存操作数 → 修正 `disp32`；
- 分支目标落在搬迁区内部 → 重定向到新地址。

仍然可能失败的场景：相对位移溢出、解码失败、自修改代码等。

### Q6：如何查看某地址的指令？

~~~cpp
HookAsm::HookRelocator reloc;
auto res = reloc.Disassemble((uint64_t)addr, 16);
for (auto& ins : res->instructions)
    printf("%p  len=%u  newLen=%u\n", (void*)ins.address, ins.length, ins.newLength);
~~~

Zydis 本身自带格式化器（`ZydisFormatter`），需要文本反汇编时可以自行组合使用。

### Q7：多线程环境如何安全使用？

~~~cpp
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
~~~

> 加锁只能保护库自身的全局容器；修改目标代码字节时，仍然要自行保证没有其他线程正在执行该区域。

### Q8：为什么 Hook 点写入 5 字节跳转，而跳板里有时用 14 字节跳转？

短跳转（`E9 rel32`）只能覆盖 ±2GB，因此：
- 跳板由 `CodeHeap` 就近分配，可以用 5 字节跳到跳板；
- 但跳板需要跳回原代码或跳到新函数，目标可能很远，所以函数 Hook 的短跳转模式会在跳板头部放一条 14 字节绝对跳转。

---

## 注意事项与最佳实践

### 重要注意事项

1. **备份原代码**：`HookBegin` 内部会备份原字节供 `HookStop` 恢复，但不要在多处重复 Hook 同一区域后随意卸载。
2. **后进先出卸载**：同一地址多次 Hook 时，`HookStop` 必须按相反顺序调用。
3. **避免递归 Hook**：回调中不要调用被 Hook 的函数（函数 Hook 请使用 `oldFunc` 返回的指针）。
4. **栈平衡**：修改 ESP/RSP 时确保栈平衡。
5. **线程安全**：全局容器无锁；修改代码页时请自行暂停 / 同步其他线程。
6. **DllMain 中少做事**：模板是在 `DLL_PROCESS_ATTACH` 中调用 `Main::init_hook()` 并另起线程执行 `Main::run()`；在加载锁内做复杂操作容易死锁。

### 最佳实践

1. **最小化 Hook 范围**：只在必要位置 Hook，优先选择指令边界清晰的位置。
2. **快速回调**：回调应尽快返回，避免阻塞目标线程。
3. **错误处理**：始终检查返回值，`ErrorDisAsmFailed` / `ErrorAsmFailed` 通常意味着 Hook 点选择不当。
4. **资源清理**：程序退出前卸载全部 Hook，并释放 `Asm_Ret` / `Asm_Mov_*_And_Jmp` 生成的代码。
5. **优先短跳转**：x64 上优先使用默认的短跳转模式，减少被覆盖的字节数；只有当就近分配失败时才使用 `isUseLongJump`。

### 性能优化建议

1. **批量安装**：一次性安装多个 Hook，避免频繁创建 / 销毁堆与页。
2. **避免频繁 Hook / Unhook**：频繁操作会产生内存碎片，`CodeHeap` 也需要反复 `VirtualAlloc` / `VirtualFree`。
3. **选择低频执行的位置**：跳板保存 16 个寄存器 + RFLAGS 有一定开销。
4. **不需要原代码时用 `OriginalCodeLocation_Without`**：跳板更短，也不需要搬迁指令。

---

## 依赖库说明

### Zydis

| 项目 | 内容 |
|------|------|
| 版本 | 5.0.0（`ZYDIS_VERSION = 0x0005000000000000`） |
| 用途 | 指令解码、长度分析、分支与 RIP 相对寻址识别 |
| 许可 | MIT |
| 文件 | `HookAsm/Zydis/Zydis.h`、`HookAsm/Zydis/Zydis.c`（amalgamated 单文件） |
| 编译宏 | `ZYDIS_STATIC_BUILD` |

### AsmJit

| 项目 | 内容 |
|------|------|
| 版本 | 1.23.0（`ASMJIT_LIBRARY_VERSION`） |
| 用途 | 运行期生成调用回调的跳板机器码（使用其 x86 汇编器） |
| 许可 | Zlib |
| 目录 | `HookAsm/asmjit/` |
| 编译宏 | `ASMJIT_STATIC` |

> 已移除：**Capstone**（旧的反汇编引擎）与 **AsmTk**（旧的汇编文本解析器）。源码中可能还能看到注释掉的 `capstone.lib` 引用，属于历史残留。

---

## 许可证信息

本项目采用 Apache License 2.0 许可证（见 `LICENSE.txt`）：

~~~
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
~~~

### 第三方库许可证

| 库 | 许可证 |
|----|--------|
| Zydis | MIT |
| AsmJit | Zlib |

---

## 贡献指南

欢迎提交 Issue 和 Pull Request：

1. Fork 本仓库
2. 创建功能分支（`git checkout -b feature/AmazingFeature`）
3. 提交更改（`git commit -m 'Add some AmazingFeature'`）
4. 推送分支（`git push origin feature/AmazingFeature`）
5. 创建 Pull Request

---

## 联系方式

如有问题或建议，请在 GitHub 上提交 Issue。
