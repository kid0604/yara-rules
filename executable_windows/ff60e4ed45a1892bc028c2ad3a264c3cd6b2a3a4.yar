rule UACME_Akagi
{
	meta:
		description = "Rule to detect UACMe - abusing built-in Windows AutoElevate backdoor"
		author = "Florian Roth"
		reference = "https://github.com/hfiref0x/UACME"
		date = "2015-05-14"
		hash1 = "edd2138bbd9e76c343051c6dc898054607f2040a"
		hash2 = "e3a919ccc2e759e618208ededa8a543954d49f8a"
		score = 60
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "UACMe injected, Fubuki at your service." wide fullword
		$x3 = "%temp%\\Hibiki.dll" fullword wide
		$x4 = "[UCM] Cannot write to the target process memory." fullword wide
		$s1 = "%systemroot%\\system32\\cmd.exe" wide
		$s2 = "D:(A;;GA;;;WD)" wide
		$s3 = "%systemroot%\\system32\\sysprep\\sysprep.exe" fullword wide
		$s4 = "/c wusa %ws /extract:%%windir%%\\system32" fullword wide
		$s5 = "Fubuki.dll" ascii fullword
		$l1 = "ntdll.dll" ascii
		$l2 = "Cabinet.dll" ascii
		$l3 = "GetProcessHeap" ascii
		$l4 = "WriteProcessMemory" ascii
		$l5 = "ShellExecuteEx" ascii

	condition:
		(1 of ($x*)) or (3 of ($s*) and all of ($l*))
}
