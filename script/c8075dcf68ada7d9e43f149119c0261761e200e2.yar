rule powershell_alt_1
{
	meta:
		description = "Detects the presence of PowerShell usage"
		os = "windows"
		filetype = "script"

	strings:
		$a = "powershell" nocase

	condition:
		$a
}
