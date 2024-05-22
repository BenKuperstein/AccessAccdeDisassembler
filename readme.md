# Access ACCDE Disassembler
## Introduction
When saved as accde files, ms-access applications source code is stripped
away.

As described in pcodedmp (https://github.com/bontchev/pcodedmp) written by @bontchev:

>It is not widely known, but macros written in VBA (Visual Basic for Applications; the macro programming language used in Microsoft Office) exist in three different executable forms, each of which can be what is actually executed at run time, depending on the circumstances. These forms are:_
>
> - Source code. The original source code of the macro module is compressed and stored at the end of the module stream. This makes it relatively easy to locate and extract and most free DFIR tools for macro analysis like oledump or olevba or even many professional anti-virus tools look only at this form. However, most of the time the source code is completely ignored by Office. In fact, it is possible to remove the source code (and therefore make all these tools think that there are no macros present), yet the macros will still execute without any problems. I have created a proof of concept illustrating this. Most tools will not see any macros in the documents in this archive it but if opened with the corresponding Word version (that matches the document name), it will display a message and will launch calc.exe. It is surprising that malware authors are not using this trick more widely.
>
> - P-code. As each VBA line is entered into the VBA editor, it is immediately compiled into p-code (a pseudo code for a stack machine) and stored in a different place in the module stream. The p-code is precisely what is executed most of the time. In fact, even when you open the source of a macro module in the VBA editor, what is displayed is not the decompressed source code but the p-code decompiled into source. Only if the document is opened under a version of Office that uses a different VBA version from the one that has been used to create the document, the stored compressed source code is re-compiled into p-code and then that p-code is executed. This makes it possible to open a VBA-containing document on any version of Office that supports VBA and have the macros inside remain executable, despite the fact that the different versions of VBA use different (incompatible) p-code instructions.
>
> - Execodes. When the p-code has been executed at least once, a further tokenized form of it is stored elsewhere in the document (in streams, the names of which begin with __SRP_, followed by a number). From there it can be executed much faster. However, the format of the execodes is extremely complex and is specific for the particular Office version (not VBA version) in which they have been created. This makes them extremely non-portable. In addition, their presence is not necessary - they can be removed and the macros will run just fine (from the p-code).

In accde files the code is stored only the "Excode" form mentioned.

## What This Project Provides:
- Disassembly of the bytecode stored in SRP streams
- VBA7 (only 64 bit version currently) and VBA6 (only 32 bit version currently) access projects
- Resolving imports (strings, vb functions and native functions)
- Extraction of local variable names

## Example

Original VBA source code:
```vba
Sub ShowUserInput()
    Dim userInput As String
    userInput = InputBox("Please enter a number:", "Input Needed")
    
    ' Optionally, you can validate the input to ensure it's a number
    If IsNumeric(userInput) Then
        MsgBox "You entered: " & userInput, vbInformation, "Number Display"
    Else
        MsgBox "That's not a number. Please enter a valid number.", vbExclamation, "Invalid Input"
    End If
End Sub
```

Output of disassembler:
```
Function: ShowUserInput
0x0: LitVar_Missing(-0x158) [0x1f1]
0x6: LitVar_Missing(-0x128) [0x1f1]
0xc: LitVar_Missing(-0xf8) [0x1f1]
0x12: LitVar_Missing(-0xc8) [0x1f1]
0x18: LitVar_Missing(-0x98) [0x1f1]
0x1e: LitVarStr(-0x50,Input Needed<0x3>) [0x5fe]
0x26: FStVarCopyObj(-0x68) [0x649]
0x2c: FLdRf(-0x68) [0x29f]
0x32: LitVarStr(-0x20,Please enter a number:<0x4>) [0x5fe]
0x3a: FStVarCopyObj(-0x38) [0x649]
0x40: FLdRf(-0x38) [0x29f]
0x46: ImpAdCallAd(rtcInputBox<0x0>,0x38) [0x4f7]
0x4c: FStStr(userInput) [0x2b7]
0x52: FFreeVar(0xe,-0x38) [0x5ea]
0x72: FLdRf(userInput) [0x29f]
0x78: CVarRef(-0x20,0x4008) [0x3b7]
0x80: ImpAdCallAd(rtcIsNumeric<0x1>,0x8) [0x4f1]
0x86: BranchF(0xe4) [0x2c7]
0x8c: LitVar_Missing(-0xc8) [0x1f1]
0x92: LitVar_Missing(-0x98) [0x1f1]
0x98: LitVarStr(-0x20,Number Display<0x5>) [0x5fe]
0xa0: FStVarCopyObj(-0x68) [0x649]
0xa6: FLdRf(-0x68) [0x29f]
0xac: LitI4(0x40) [0x5f0]
0xb2: LitStr(You entered: <0x6>) [0x5f7]
0xb6: FLdAd(userInput) [0x297]
0xbc: ConcatStr() [0x150]
0xbe: CVarStr(-0x38) [0x371]
0xc4: ImpAdCall(rtcMsgBox<0x2>,0x28) [0x4ff]
0xca: FFreeVar(0x8,-0x38) [0x5ea]
0xde: Branch(0x138) [0x2c6]
0xe4: LitVar_Missing(-0xc8) [0x1f1]
0xea: LitVar_Missing(-0x98) [0x1f1]
0xf0: LitVarStr(-0x50,Invalid Input<0x7>) [0x5fe]
0xf8: FStVarCopyObj(-0x68) [0x649]
0xfe: FLdRf(-0x68) [0x29f]
0x104: LitI4(0x30) [0x5f0]
0x10a: LitVarStr(-0x20,That's not a number. Please enter a valid number.<0x8>) [0x5fe]
0x112: FStVarCopyObj(-0x38) [0x649]
0x118: FLdRf(-0x38) [0x29f]
0x11e: ImpAdCall(rtcMsgBox<0x2>,0x28) [0x4ff]
0x124: FFreeVar(0x8,-0x38) [0x5ea]
0x138: ExitProc() [0x27b]

```

## How To Use
### Installation
The project requires Python 3.11+.
The Access runtime used for running the file needs to be installed as well
```
git clone https://github.com/BenKuperstein/AccessAccdeDisassembler
pip install -r requirements.txt
```

### Running

```cmd
python disassemble.py --accde-file-path "path/to/your/file.accde" --output-folder-path "path/to/output/folder" --vba6
```

- `--accde-file-path` (required): Path to the ACCDE file you want to disassemble.
- `--output-folder-path` (required): Path to the folder where the disassembled code will be saved.
- `--vba6` (optional): Include this flag if the ACCDE file uses 32-bit VBA6.

## Known Issues
- The project is in an early state, there are probably lots of bugs, if your file fails to be opened by the project,
create an issue and attach the file.
- Currently only VBA7 (Access 2007+) 64 bit and VBA6 (Access 2007) 32 bit are supported
