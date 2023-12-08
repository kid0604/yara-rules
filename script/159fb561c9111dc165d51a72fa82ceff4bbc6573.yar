rule Windows_Hacktool_Mimikatz_355d5d3a
{
	meta:
		author = "Elastic Security"
		id = "355d5d3a-e50e-4614-9a84-0da668c40852"
		fingerprint = "9a23845ec9852d2490171af111612dc257a6b21ad7fdfd8bf22d343dc301d135"
		creation_date = "2021-04-14"
		last_modified = "2021-08-23"
		description = "Detection for Invoke-Mimikatz"
		threat_name = "Windows.Hacktool.Mimikatz"
		reference_sample = "945245ca795e0a3575ee4fdc174df9d377a598476c2bf4bf0cdb0cde4286af96"
		severity = 90
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "script"

	strings:
		$a1 = "$PEBytes32 = \"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAEAAA4fug4AtAnNIbgBTM0hVGhpcyBwc"
		$a2 = "$PEBytes64 = \"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAEAAA4fug4AtAnNIbgBTM0hVGhpcyBwc"
		$b1 = "Write-BytesToMemory -Bytes $Shellcode"
		$b2 = "-MemoryAddress $GetCommandLineWAddrTemp"
		$b3 = "-MemoryAddress $GetCommandLineAAddrTemp"
		$c1 = "Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes64, $PEBytes32, \"Void\", 0, \"\", $ExeArgs)" fullword
		$c2 = "Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes64, $PEBytes32, \"Void\", 0, \"\", $ExeArgs) -ComputerNam"
		$c3 = "at: http://blog.gentilkiwi.com"
		$c4 = "on the local computer to dump certificates."
		$c5 = "Throw \"Unable to write shellcode to remote process memory.\"" fullword
		$c6 = "-Command \"privilege::debug exit\" -ComputerName \"computer1\""
		$c7 = "dump credentials without"
		$c8 = "#The shellcode writes the DLL address to memory in the remote process at address $LoadLibraryARetMem, read this memory" fullword
		$c9 = "two remote computers to dump credentials."
		$c10 = "#If a remote process to inject in to is specified, get a handle to it" fullword

	condition:
		(1 of ($a*) or 2 of ($b*)) or 5 of ($c*)
}
