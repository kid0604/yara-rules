rule escalate_priv
{
	meta:
		author = "x0r"
		description = "Escalade priviledges"
		version = "0.1"
		os = "windows"
		filetype = "executable"

	strings:
		$d1 = "Advapi32.dll" nocase
		$c1 = "SeDebugPrivilege"
		$c2 = "AdjustTokenPrivileges"

	condition:
		1 of ($d*) and 1 of ($c*)
}
