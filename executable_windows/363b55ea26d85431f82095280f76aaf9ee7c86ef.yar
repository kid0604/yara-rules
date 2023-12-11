rule win_token
{
	meta:
		author = "x0r"
		description = "Affect system token"
		version = "0.1"
		os = "windows"
		filetype = "executable"

	strings:
		$f1 = "advapi32.dll" nocase
		$c1 = "DuplicateTokenEx"
		$c2 = "AdjustTokenPrivileges"
		$c3 = "OpenProcessToken"
		$c4 = "LookupPrivilegeValueA"

	condition:
		$f1 and 1 of ($c*)
}
