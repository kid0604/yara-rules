import "pe"

rule MALWARE_Win_PWSHDLLDL
{
	meta:
		author = "ditekShen"
		description = "Detects downloader"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "powershell.exe Set-ExecutionPolicy Bypass -Scope Process ; powershell -file " fullword wide nocase
		$s2 = "objShell.run \"powershell -WindowStyle hidden -command wscript.exe //b //nologo '" fullword wide nocase
		$s3 = "cmd.exe /c schtasks.exe /create /tn \"" fullword wide nocase
		$s4 = "-WindowStyle hidden -command wscript.exe //b //nologo '" fullword wide nocase
		$s6 = "\" /tr \"wscript.exe //b //nologo '" fullword wide nocase
		$s7 = "\" -Value \"Powershell.exe -WindowStyle hidden \"\"& '" fullword wide nocase
		$op0 = { 61 01 00 34 53 79 73 74 65 6d 2e 57 65 62 2e 53 }
		$op1 = { 4b 04 00 00 34 01 00 00 7f 05 00 00 1a }

	condition:
		uint16(0)==0x5a4d and pe.is_dll() and 5 of them
}
