
sampleOut="""
********************
********************
Here is also a sample output in text format. Please adhere to the keys and values in the sample dictionary and use those to help create content similar to the below.

### MITRE ATT&CK Techniques:

**T1071.001 - Application Layer Protocol: Web Protocols**
- **Description:** The URLDownloadToFileA function is used to download a file from a specified URL. This is characteristic of the T1071.001 technique where adversaries use application layer protocols to communicate and download files.
- **Appearances:** 0x64-0x70 (URLDownloadToFileA)

**T1059.003 - Command and Scripting Interpreter: Windows Command Shell**
- **Description:** The CreateProcessA function is used to execute commands via the Windows Command Shell (cmd.exe). The specific command executed is `cmd.exe /c test.bat`, indicating the use of a command shell to run a script.
- **Appearances:** 0x15e-0x170 (cmd.exe /c test.bat)

**T1105 - Ingress Tool Transfer**
- **Description:** The URLDownloadToFileA function is used to download a file (`test.bat`). This demonstrates the T1105 technique where adversaries transfer tools or files from an external system into the network.
- **Appearances:** 0x64-0x70 (URLDownloadToFileA)

**T1070.004 - Indicator Removal on Host: File Deletion**
- **Description:** The DeleteFileA function is used to delete the file `test.bat` after it has been executed. This is indicative of the T1070.004 technique where adversaries remove files to hinder forensic analysis.
- **Appearances:** 0xa0-0xae (DeleteFileA)

**T1497 - Virtualization/Sandbox Evasion**
- **Description:** The Sleep function is used to delay execution for a specified time (`0x3000` milliseconds). This technique can be used for sandbox evasion by delaying execution to outlast automatic analysis.
- **Appearances:** 0x8e-0x9a (Sleep)

### Most Critical Technique: 

**T1105 - Ingress Tool Transfer:**
- **Description:** This technique is critical because it involves downloading external files (`test.bat`) which can be used to introduce malicious tools or scripts into the network, potentially leading to further exploitation.
- **Appearances:** 0x64-0x70 (URLDownloadToFileA)

### Techniques Summary:

The analyzed sample utilizes several MITRE ATT&CK techniques to carry out its actions. It employs T1071.001 to use web protocols for downloading files via the URLDownloadToFileA function. The command shell execution (T1059.003) indicates the use of CreateProcessA to run a downloaded batch file (`test.bat`). The same function call aligns with T1105 by transferring this file from an external source. Furthermore, it uses T1070.004 to delete the batch file and remove any evidence, employing the DeleteFileA function. To evade detection, it employs T1497 by using the Sleep function to delay execution.

### WinAPIs:

**WinAPI - URLDownloadToFileA:**
- **Definition:** Downloads a file from a specified URL.
- **Usage:** Used to download `https://167.99.229.113/default.css` to `test.bat`, aligning with T1071.001 and T1105.

**WinAPI - CreateProcessA:**
- **Definition:** Creates a new process and its primary thread.
- **Usage:** Executes `cmd.exe /c test.bat`, aligning with T1059.003.

**WinAPI - VirtualAlloc:**
- **Definition:** Reserves or commits a region of memory within the virtual address space.
- **Usage:** Allocates memory for further shellcode or data storage.

**WinAPI - Sleep:**
- **Definition:** Suspends the execution of the current thread for a specified interval.
- **Usage:** Suspends execution for `0x3000` milliseconds, aligning with T1497.

**WinAPI - DeleteFileA:**
- **Definition:** Deletes an existing file.
- **Usage:** Deletes `test.bat` after execution, aligning with T1070.004.

**WinAPI - ExitProcess:**
- **Definition:** Ends the calling process and all its threads.
- **Usage:** Terminates the process after completion of tasks.

### Artifacts Summary:

The artifacts `urlmon.dll` and `test.bat` are significant in this sample. `urlmon.dll` is imported to facilitate the use of URLDownloadToFileA, which downloads an external batch file (`test.bat`). This batch file is then executed and subsequently deleted, indicating a potential malicious script or tool being run and then erased to avoid detection.

### Executive Summary:

The analyzed shellcode demonstrates a sophisticated execution flow starting by downloading a batch file from an external URL using URLDownloadToFileA. It then executes this downloaded file using the Windows Command Shell (cmd.exe) via CreateProcessA. Post-execution, the shellcode delays with Sleep to evade sandbox analysis and finally deletes the batch file using DeleteFileA to remove traces. The use of VirtualAlloc suggests memory management possibly for loading further shellcode or data. Overall, the operations indicate a structured approach to downloading, executing, and concealing malicious activities. The usage of syscalls instead of WinAPIs, where applicable, can indicate an attempt by the author to be more stealthy and sophisticated in their methods.

### Comprehensive Analysis of Disassembly and Data

#### Overview

The disassembly indicates structured steps for downloading, executing, and deleting files. The DWORDs offer placeholders for API pointers and various checksum values, which assist in the resolution of function addresses.

### Detailed Analysis

1. **GetPC and Jump to Code Execution:**
   - **Address Range:** 0x0-0x6
   - **Description:** Obtains the current program counter and adjusts it, setting up the execution flow.
   - **Example:** `call 5; pop edx; lea edx, [edx - 5]`

2. **Initial Setup and Calls:**
   - **Address Range:** 0x7-0x34
   - **Description:** Sets up initial registers and values for execution.
   - **Example:** `mov ebx, 0x4b1ffe8e; call 0xc3`

3. **API Calls Setup:**
   - **Address Range:** 0x35-0xbe
   - **Description:** Prepares and calls various WinAPIs like LoadLibraryA, URLDownloadToFileA, Sleep, DeleteFileA, and CreateProcessA.
   - **Example:** `call dword ptr [edx + 0x1bb]; call eax`

4. **Function Resolution Using PEB walking:**
   - **Address Range:** 0xc3-0xf8
   - **Description:** Walks through the Process Environment Block (PEB) to resolve function addresses.
   - **Example:** `mov edi, dword ptr fs:[0x30]; mov esi, dword ptr [edi + 0x28]`

5. **API Pointers and Memory Addresses:**
   - **Address Range:** 0x1af-0x1cf
   - **Description:** Contains placeholders for API pointers and strings used for function calls.
   - **Example:** `CreateProcessA - API pointer; VirtualAlloc - API pointer`

6. **Hashing Routine:**
   - **Address Range:** 0xe8-0xf6
   - **Description:** Uses rotate and XOR operations to calculate hash values for string comparison.
   - **Example:** `rol edx, 7; xor dl, al`

   

7. **Strings and Data:**
   - **Address Range:** 0x1d3-0x214
   - **Description:** Contains critical strings like `urlmon.dll`, `cmd.exe /c test.bat`, and `http://167.99.229.113/default.css`.
   - **Example:** `urlmon.dll; cmd.exe /c test.bat; test.bat`

8. **Function Names:**
   - **label_0x5:** Shellcode Entry Point 
   - **Start of function:** X
   - **End of function:**Y
   - **label_0x10:** Download File Function 
   - **Start of function:** X
   - **End of function:**Y
   - **label_0x15a:** Execute and Cleanup Function
   - **Start of function:** X
   - **End of function:**Y

### Purpose of Recognized DWORDs

**Checksum Values:**
- **Address Range:** 0x193-0x1ab
- **Example:** `dd c78a3146; dd dff0f081`

**Placeholders for API Pointers:**
- **Address Range:** 0x1af-0x1cf
- **Example:** `CreateProcessA - API pointer; DeleteFileA - API pointer`

### Concluding Remarks

The shellcode demonstrates a systematic approach to downloading, executing, and erasing files. The disassembly reveals multiple techniques used for various stages, from setting up execution context, downloading files via web protocols, executing scripts using command shells, and finally performing cleanup by deleting evidence. The use of sophisticated techniques like PEB walking and hashing routines for API resolution indicates the malware's intent to evade detection and ensure successful execution within the victim system.

"""


prompt_A ="""INITIAL PROMPT

Do not use any asteriks (*) in your response. It is acceptable only if it is present in the material you are analyzing and you are quoting it. 
Analyze these APIs and their parameters to determine which MITRE ATT&CK techniques they correspond to. Additionally, consider file artifacts when trying to determine what MITRE ATT*CK techniques they may correspond to. Please format your response as such. Each should have a Definition and a Usage subsection - see below:

The MITRE ATT&CK Techniques:

For each of the the techniques you list, please try to provide as much as 4-6 sentences describing why this MITRE ATT&CK technique might be present, using specific details to support this. If there is simply not enough to go on, then you can have a minimum of two sentences with supporting details. Part of this can also involve restating what the specific MITRE ATT&CK is (no more than one sentence).
T100X - MITRE ATT&CK Technique Name:
- Description: Provide a detailed description of why this shellcode exhibits this technique. The description must mention specific features from the sample that lead you to believe this technique is being used. If possible, provide 4-6 sentences of description. More is acceptable if there is a lot to share. If there is not enough to go on, then 2 sentences is acceptable.
- Appearances: The appearances subheading for each technique tells where it appears in the disassembly. Can you identify the specific lines of code where a technique may be in place? It can be in place in more than one places. Please also pay attention to parameters. If there are five parameters, then there likely are five pushes to put those parameters onto the stack, though this may not necessarily always be the case. Your response should be a range of addresses, not a single line. For instance 0xab-0xbd, 0xde-0xf2. Do not include entire lines, only ranges. If you wish to include parenethentical comments for certain ranges, that is acceptable, such as 0x123-0x128 (CreateProcessA)

Here is an example of one from a sample:
**T1197 - BITS Jobs:**
- **Description:** The URLDownloadToFileA function indicates an attempt to download a file from a URL. This is characteristic of the T1197 technique where adversaries use Background Intelligent Transfer Service (BITS) to download files. The specific function URLDownloadToFileA and the provided URL parameters indicate this activity.
- **Appearances:** 0x64-0x70 (URLDownloadToFileA)


Most Critical technique: Identify the MITRE technique present in the sample that appears to be the most alarming or most critical. This is the one that potentially could do the most damage. Be sure to include this section. 

Note that VirtualAlloc probably does not indicate process injection, T1055. We would want to see VirtualAllocEX going into an external process. Please do not indicate process injection, T1055, if VirtualAlloc is used. You can assume in this case VirtualAlloc is being used for some other purpose. Again supress T1055 if VirtualAlloc is being used; only indicate process injection if you see VirtualAllocEx. Do not identify Process Injection unless you see at least four APIs or WinAPIs associated with process injection. VirtualAlloc by itself is insufficient, as process injection requires movement to an external process, not the current process. Do not write anything about Process injection unless the above requirements are satisfied. Again, if you have just VirtualAlloc, do not indicate process injection.

Do not, absolutely do not, do not list any MITRE ATT&CK techniques unless indicated by functions present. Do NOT guess or speculate if no supporting functions are present, unless there are other clues, such as relevant strings or other malicious indicators.

Techniques Summary: Provide a summary of the techniques used in the malware sample. This should not be a listing, but should be a cohesive paragraph. If possible, tie together the techniques. Be sure to explicitly name the techniques being used.

The WinAPIs:

WinAPIs: Look at each WinAPI or function used and tell how it appears to be used maliciously in this sample. Each WinAPI should be labeled like the following. The usage section should provide specific details from the shellcode sample. Note: It is possible that instead of WinAPIs, Windows syscalls may be used. This is an alternative, covert method of invoking Windows functionality. If this is the case, then the function will appear onot under the WinAPI heading, but instead the Syscall heading. If this happens, thenn please use the syscall label rather than WinAPI label. 

WinAPI - VirtualAlloc: This is just an example of one Winapi. Provide definition, and tell specifically what it appears to be doing in this sample. If you can tie it together with MITRE ATT&CK framework, that is best. If there is no connection apparent to MITRE, then just report on what the WinAPI appears to be doing. Each should have a Definition and a Usage subsection - see below:

WinAPI - DeleteFileA:
- Definition: Deletes an existing file. 
- Usage: Deletes `test.bat` after execution, aligning with the T1070.004 technique.

Artifacts Summary: Provide an executive summary of the artifacts, highlighting the most important ones. If you can tie them together to a malicious activity or known technique, do so, but only if the evidence supports it. Do not include DLLs or discuss DLLs in the artifacts summary. Otherwise, if the above is not possible, just summarize the signifiance of the artifacts, while omitting DLLs. What is the signficance of these artifacts in this sample? 

Executive Summary: Provide an overall description of what the shellcode is doing, without mentioning anything from MITRE ATT&CK Framework. If syscalls are used, rather than WinAPIs, please make a note of this and mention that these can be more stealthy and indicate greater sophistication from the author.

Every heading or subheading should be like a key value pair and be delimited by a colon (:). Do not mix the two sections on WinAPIs and MITRE ATT&CK techniques. Each has its own section. WinAPIs can mention MITRE ATT&CK techniques if relevant.

Make sure to include all required outputs, the MITRE ATT&CK techniques, the Most Critical technique, Techniques Summary, the WinAPIs, the Artifacts Summary, and Executive Summary. Any final comments can be added into Executive Summary. All the above must be present. 
"""




dwords_A="""
DWORDS PROMPT
Additionally, analyze some of the dwords that are in the code. This is hexadecimal that begins with dd. There usually will be multiples of these, such as dd 0xbad134 or dd 0x4433. With this disassembly, we have already determined that this is memory that is being written to or read fom. Given the context of the shellcode, what is the probable purpose of any dwords you may see? Can you figure anything out? Please note there may be no dwords in the disassembly provided. There can also be in shellcode dword arrays, or arrays of dwords, and there can be two parts to this. The first is some checksum value that be used to help resolve an API address. That is, each API address might be hashed, and the shellcode may look for two matching hashes, indicating it found an API address. The second purpose for the dword array is for it to serve as a placeholder for a memory address, which is resolved. In the disassembly, if the tool has been able to figure this out, it will have a " - API pointer" follow it, though it is possible there are no API pointers. That memory address will be updated to hold the runtime address for an API. If it says " - API Pointer" - then we have already determined that it serves to hold the runtime address for that funciton. Given all the above, please provide a comprehensive analysis of the dwords present, and also other parts of the disassembly that is non-code or not instructions.  Please note there may be no dword arrays present. If so, please state this. Please also note that the ASCII or even Unicode of a string could be used for comparison; that does not mean it is not a checksum. Dwords is rather generic and can encompass many different types of data. do not falsely identify something such as ASCII from a string as being a checksum.

If a runtime address of a function is resolved and stored somewhere, then you should be able to call it from that memory location, which may be pointed to by a reference. So it could be called from an offset in the dword array, e.g. edi+0x1badd might point to some function, whose address was resolved.

Sometimes shellcode will calculate the hash of a string for a function until it finds the match of a pre-calcualted hash for a desired function. This hashing routine is often a part of of the shellcode itself - though not necessarily. Can you identify the hashing routine? If so, identify it and explain how it works in the Hashing Routine section below. If hashing routine is found, identify the range it occupies, e.g. 0xde-0xfd. If doing things with rotate or XOR, identify the specific numerical values in question. If no hashing routine found, then skip. Under description, explain the hashing routine in plain language.

These are possible sections that you can have in the final report. Try to follow these self-explanatory headings and subheadings. IF one is not present, then skip it. For instance, if there are no intiail setup and calls, skip it. Additionally, for detailed analysis, add other subheadings as necessary, even if they are not in the list below. Do what is best to support the analysis of this shellcode

In the disassembly, there are labels, which mean that there is some "jmp", "call", or similar control flow transfer to that location. If you see a label that ends with a return or "ret", analyze that snippet of code. Suggest a function name for the code. For instance, a label might be in this format label_0x15e: That would mark the beginning and ret would mark the end. You should analyze and look at the shellcode to find each label_0xYY. That is potentially the start of a function. Thus, if you have label_0x15e, you could have a function that begins at label_0x15e. You may not arbitarily start functins at places where there is not a label. Additionally, the funciton must terminate in a ret. Thus, a function may span a range of 5 or 20 or even 54 bytes, beginning with a label and ending with a ret. Our goal is to analyze the functionality of what is happening in that function and rename it. Thus, label_0x15e might become Download_File_Function. If there is no label there, then you cannot create a function there. The function names will go in the Suggested Function Names section. You should suggest a function name for every function found. Again, it is imperative that each function must start in the disassembly provided with label_0xYY and end with a ret, as we are trying to analyze the functions and come up with a suitable name. We are not trying to map out what goes on in each area of the code. It is possible there may be no functions or only one or two. Try to find as many functions as you can while strictly following the above.  This is supposed to be analogous to renaming functions you might find in disassembly for IDA Pro or Ghidra.

Please note that it is important for the below: provide ALL examples from the disassembly that may fall under that heading. If more than 10 examples for one category or sub-category, may list the top 10.

1 ### Comprehensive Analysis of Disassembly and Data
#### Overview
Overview - give an overview of the disassembly as it pertains to DWORDs. 

### Detailed Analysis
Detailed Analysis - title for section with different sub-sections, including:
1. **GetPC and Jump to Code Execution:** - Provide specific address or range of addresses. Provide a description of what is going on and an example.
2. **Initial Setup and Calls:**- Provide specific address or range of addresses. Provide a description of what is going on and an example.
3. **API Calls Setup:**  - Provide specific address or range of addresses. Provide a description of what is going on and an example.
4. **Function Resolution Using PEB walking:** - Provide specific address or range of addresses. Provide a description of what is going on and an example.
5. **API Pointers and Memory Addresses:**  - PLEASE LIST ALL OF THESE, providing specific address or range of addresses. Provide an explanation/description.
6. **Hashing Routine:** - Provide specific address or range of addresses. Provide an explanation/description. Under description, explain the hashing routine in plain language.
    - **Address range:** Gives address range.
    - **Description:** Provides a plain language explanation/description of what is going on in the hashing routine. If no hashing routine, put Not present.
    - **Example:** Provide the Assembly of the hashing routine. Can seprate different lines of code with semi-colon (;).
7. **Strings and Data:** PLEASE LIST ALL OF THSE, providing specific address or range of addresses, up to a maximum of the 10 most important examples. If any of these are security-relevant, please add comments under its description. 
    - **Address range:** Range of bytes occupied by the string
    - **Description:** Any comments on possible purposes of string, especially if security-relevant or related to malicious funcitonality.
    - **Example:** Give the string in string format (NOT hexadecimal)
    - **Possible Malcious Usage:** Can you speculate on any possible malicious usage for this string, as supported by facts in the disassembly or as it relates to identified MITRE ATT&CK techniques?

8. **Suggested Function Names:** Please list ALL of these! -Provide specific address or range of addresses. Shoudl be formated like this: label_0x5: Shellcode Entry Point  Again, as described before, you can only start a function where there is a label_0xYY (format) in the disassembly, and where it ends in a ret. Otherwise, You should come up with a function name for every function that adheres to that format (label_0xYY to a ret). Additionally, you should provide a " "Start of function", which gives the address where the function starts, and then an             "End of function", which shows where it ends.
	Note: that is just an example.
    - **label_0xXY:** Sample Function name, Shellcode Entry Point
    - **Start of function:** "0x5"
    - **End of function:**"0x8"
9. **Comments on Dynamic API Resolution:** Analyze the disassembly and if there are any areas where there are not already comments pertaining to  dynamic API resolution, suggest a comment and the corresponding address. For instance, is there something from Windows internals or PE file format that is being manipulated to help make this work? This could be a specific offset that aligns to a known structure or value. Do not make stuff up. Only provide if it is documented in your knowledge base. IF I already have a comment there, then do not add a new comment. These should not be comments from the disassembly. We already know about those. We are looking for new comments that can be provided due to your analysis.
    - **Address:** "Sample address for suggested comment.",
    - **Comment:** "Suggested comment pertaining to  dynamic API resolution."
10. **Obfuscation:** 
    - **Description:** If the shellcode used a decoder stub, then it relied on an encoding algorithm. Try to describe this in detail if you can, explaining how it worked. How does the shellcode decode itself? What does that suggest is likely in terms of the initial encoding algorithm?  If any other obfuscation is used, then please list and describe those. For each, you may place an address range after the sentences describing it, whether a decoder stub, or other obfuscation.

11. **Other Comments of Note:"** If there are any other parts of the disassembly that are noteworthy or unique for any reason, and have not already been addressed in other sections, provide a comment here. These should not be comments from the disassembly. We already know about those. We are looking for new comments that can be provided due to your analysis.
    - **Address:** "Sample address for comment.",
    - **Comment:** "Comment on some item or feature of note."

### Purpose of Recognized DWORDs
- **Checksum Values:**  - PLEASE LIST ALL OF THESE, providing specific address or range of addresses. If purpose is known, please provide it.
    NOTE: Each checksum should be listed individually, not discussed as a group.
    - **Address:** "Sample range for checksum values."
    - **Description:** "Sample description for checksum values. Can you figure out what WinAPI this checksum is being used for? If so, please list it. If you analyze the shellcode carefully, it is probably apparent which WinAPI the checksum corresponds to.  If none present, put Not available."
    - **Example:** "dd c78a3146"

- **Placeholders for API Pointers:** - PLEASE LIST ALL OF THESE, providing specific address or range of addresses.
    NOTE: Each placehholder should be listed individually, not discussed as a group.
    - **Address range:** "Sample range for API pointers. Give specific addresses, if any."
    - **Example:** "Sample description for API pointers. If none present, put Not available"
### AI Model
- Provide the AI model used for this analysis.
### Concluding Remarks
- Provide concluding remarks for this section, focusing on the disassembly and what it is doing, no need to mention Mitre techniques. Look at disassembly without the need to worry about MITRE.

Very important: IF you have multiple lines of Assembly on any one line, please delimit or seperate them with a semi-colon (;), not a comma (,).  
See the disassembly below:

"""

sample_dict="""
sample_dict

Remember for MITRE ATT&CK Techniques, ideally should be 4-6 sentences for each description.

The sample_dict follows:

test_template = {
    "MITRE ATT&CK Techniques": {
        "T1xxx - Sample MITRE technique 1": {
            "Description": "Sample description for sample MITRE technique 1.",
            "Appearances": "Sample appearances for sample MITRE technique 1."
        },
        "T1xxx - Sample MITRE technique 2": {
            "Description": "Sample description for sample MITRE technique 2.",
            "Appearances": "Sample appearances for sample MITRE technique 2."
        }
    },
    "Most Critical Technique": {
        T1xxx - Most Critical MITRE technique": {
            "Description": "Sample description for most critical MITRE technique 1 - explains why it is most critical",
            "Appearances": "Sample appearances for most critical MITRE technique 1"
    }
    

    "Techniques Summary": "Sample techniques summary in the form of highly detailed paragraph, citing specific techniques.",
    "WinAPIs": {
        "WinAPI - Sample WinAPI Name 1": {
            "Definition": "Sample definition for Sample WinAPI 1.",
            "Usage": "Sample usage for Sample WinAPI 1."
        },
        "WinAPI - Sample WinAPI Name 2": {
            "Definition": "Sample definition for Sample WinAPI 2.",
            "Usage": "Sample usage for Sample WinAPI 2."
        }
    },
    "Artifacts Summary": "Sample artifacts summary.",
    "Executive Summary": "Sample executive summary in highly detailed paragraph.",
    "Comprehensive Analysis of Disassembly and Data": {
        "Overview": "Sample overview.",
        "Detailed Analysis": {
            "GetPC and Jump to Code Execution": {
                "Address range": "Sample range for GetPC and Jump to Code Execution.",
                "Description": "Sample description for GetPC and Jump to Code Execution. If none present, put Not available",
                "Example":"Provides an example of GetPC and jump to code execution. If none present, put Not available"
            },
            "Initial Setup and Calls": [
                {
                    "Address range": "Sample range for initial setup and calls.",
                    "Description": "Sample description for initial setup and calls. If none present, put Not available",
                    "Example":"Provides an example of initial setup and calls. If none present, put Not available"

                }
            ],
            "API Calls Setup": [
                {
                    "Address range": "Sample range for API calls setup 1.",
                    "Description": "Sample description for API calls setup. If none present, put Not available"
                },
                {
                    "Address range": "Sample range for API calls setup 2.",
                    "Description": "Sample description for API calls setup. If none present, put Not available"
                }
            ],
            "Function Resolution Using PEB Walking": {
                "Address range": "Sample range for function resolution using PEB walking.",
                "Description": "Sample description for function resolution using PEB walking."
            },
            "API Pointers and Memory Addresses": [
                {
                    "Address range": "Sample range for API pointers and memory addresses 1.",
                    "Description": "Sample description for API pointers and memory addresses. If none present, put Not available"
                },
                {
                    "Address range": "Sample range for API pointers and memory addresses 2.",
                    "Description": "Sample description for API pointers and memory addresses. If none present, put Not available"
                }
            ],
            "Hashing Routine": {
                "Address range": "Sample range for hashing routine.",
                "Description": "Sample description for hashing routine. If none present, put Not available",
                "Example":"Provides an example of the hashing routine from the code. If none present, put Not available"

            },
            "Strings and Data": [  ##List each string and data separately.  Can have up to 100 listed here.
                {
                    "Address range": "Sample range for strings and data 1.",
                    "Description": "Sample description for strings and data. Any comments on possible purposes of string, especially if security-relevant or related to malicious funcitonality. If none present, put Not available",
                    "Example":"Provides an example strings or data for this instance. If none present, put Not available",
                    "Possible Malcious Usage": "Can you speculate on any possible malicious usage for this string, as supported by facts in the disassembly or as it relates to identified MITRE ATT&CK techniques?"


                },
                {
                    "Address range": "Sample range for strings and data 2.",
                    "Description": "Sample description for strings and data.Any comments on possible purposes of string, especially if security-relevant or related to malicious funcitonality.  If none present, put Not available",
                    "Example":"Provides an example strings or data for this instance. If none present, put Not available"

                },
                {
                    "Address range": "Sample range for strings and data 3.",
                    "Description": "Sample description for strings and data.Any comments on possible purposes of string, especially if security-relevant or related to malicious funcitonality. ",
                    "Example":"Provides an example strings or data for this instance. If none present, put Not available"

                }
            ],
            "Suggested Function Names": [    # Function names shoudl use _ instead of spaces.
                {
                    "label_0xXY": "Sample Function name, Shellcode_Entry_Point",
                    "Start of function": "0x5",
                    "End of function":"0x8"

                },
                {
                    "label_0xXY": "Sample Function name, Download_File_Function",
                    "Start of function": "0x64",
                    "End of function":"0x70"
                }
            ],
            "Comments on Dynamic API Resolution": [   # This is a list with multiple comments
                {
                    "Address": "Sample address for suggested comment.",
                    "Comment": "Suggested comment pertaining to dynamic API resolution."
                }
            ],
            ,
            "Obfuscation": [ ##List each instance of obfuscation separately as an element of a list.  Only one is shown here. This MUST be in list format, even if there is only one. You MUST provide the starting adddress for address range and ending address as well.
             {      #Example 1
                    "Description": "Provide description of the encoding algorithm if present as seen in decoder stub and any other obfuscation attempts",
                    "Address range":"Provide address range for this specific instance."
                },
             {      #Example 2
                    "Description": "Provide description of the encoding algorithm if present as seen in decoder stub and any other obfuscation attempts",
                    "Address range":"Provide address range for this specific instance."
            }
            ],
            "Other Comments of Note": [
             {
                    "Address": "Sample address for comment.",
                    "Comment": "Comment on some item or feature of note."
                }
            ]

        },
        "Purpose of Recognized DWORDs": {
            "Checksum Values": [  ## List each checksum by itself. Can have up to 100 listed here.
                {
                    "Address": "Sample range for checksum value 1.",
                    "Discussion": "Sample discussion of what is going on with the checksum values. If nothing can be figured out about what these are, then just put that they are suspected to be checksums. If it is possible to figure out what WinAPI this checksum is being used for, then identify it. If none present, put Not available",
                    "Example": "dd c78a3146"
                },
                {
                    "Address range": "Sample range for checksum value 2.",
                    "Discussion": "Sample discussion of what is going on with the checksum values. If nothing can be figured out about what these are, then just put that they are suspected to be checksums. Can you figure out what WinAPI this checksum is being used for? If so, please list it. If none present, put Not available",
                    "Example": "dd dff0f081"
                }
            ],
            "Placeholders for API Pointers": [  ## List each pointer by itself. Can have up to 100 listed here.
                {
                    "Address range": "Sample range for API pointer #1. Give specific addresses, if any.",
                    "Example": "Sample description for API pointer #1. If none present, put Not available"
                },
                {
                    "Address range": "Sample range for API pointer #2. Give specific addresses, if any.",
                    "Example": "Sample description for API pointers.#2 .If none present, put Not available"
                }
                
            ]
        },
        "AI Model":"Give the AI model used",
        "Concluding Remarks on Disassembly": "Sample conclusion."
    }
}
"""
finalAI="""For each of the above items, please convert into a well defined Python diction - i.e. break each component into a key value pair. ONLY RETURN THIS OUTPUT AS A WELL FORMATTED DICTIONARY. Do not include anything not inside the dictionary. Thus, if Python were to take the output and do type() on it, then your output would be type==dict.
There sould be no additional text surrounding this. No ```python or no ```  or no "python". Just give the dict by itself!! A sample dict with the desired format follows. Keep same key names in the sample dictionary. If there are no examples, then simply write as the value Not present or similar. In instances of lists, add as many as needed. With dictionaries that are nested within other dictionaries, there can be as many as entries as need be. For instances, for MITRE ATT&CK Techniques, there can be anywhere from 0 to infinite techniques. Always have at least one, but otherwise, have as many as can be found. Do not create other keys that what is present. Do not modify the key names in anyway, as we may expect them to formed exactly as they are. Do not add _ between words. Do not change capitalization, spelling, or punctuation for key names.
"""

finalAI2="""Remember all elements in the dictonary must be present - all keys and respective values, corresponding to the above. The names for the keys must be absolutely identical to what is in the example dictionary!! The output must be type == dict (dictionary), with no ``` and no python. It should be all contained within the  {}. Please use all keys such as "Description" and "Address range" if they are present in the example dictionary that is to follow. If it is in the example dictionary as a key, it should be in yours as well. Your answer must closely mirror what is in the example dictionary in terms of structure with no deviation.
"""

finalAI3="""Remember again that everything present must be asked of you must be present including the DWORD PROMPT, the initial prompt, and adhere to the sample_dict provided.

     The names for the keys must be absolutely identical to what is in the example dictionary!! The output must be type == dict (dictionary), with no ``` and no python. It should be all contained within the  {}. Please use all keys such as "Description" and "Address range" if they are present in the example dictionary that is to follow. If it is in the example dictionary as a key, it should be in yours as well. Your answer must closely mirror what is in the example dictionary in terms of structure with no deviation. Do not arbitarily create other things to add to the dictionary, and do not rename things found in the dictionary.
"""
# completePrompt=prompt_A  + g_unencodedAPIS +  g_unencodedDis + dwords_A + g_unencodedDis
# completePrompt= dwords_A + g_unencodedDis
# completePrompt=prompt_A  + alexEm +  alexDis + dwords_A + alexDis
# completePrompt=prompt_A  + g_unencodedAPIS +  g_unencodedDis + dwords_A + g_unencodedDis + finalAI + finalAI2 + sample_dict
# completePrompt=prompt_A  + samAPI +  g_unencodedDis + dwords_A + samDIS
# completePrompt=prompt_A  + regAPI +  g_unencodedDis + dwords_A + regDis
# completePrompt=prompt_A  + winsysAPI  + dwords_A + winsysDIS
# completePrompt=prompt_A  + jwApi  + dwords_A + jwDIS
# completePrompt=prompt_A  + shelSysAPI  + dwords_A + shelSysDis

# completePrompt=prompt_A  + g_unencodedAPIS +  g_unencodedDis + dwords_A + g_unencodedDis + finalAI + finalAI2 + sample_dict

