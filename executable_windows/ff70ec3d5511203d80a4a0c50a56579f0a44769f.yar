rule win_registry
{
	meta:
		author = "x0r"
		description = "Affect system registries"
		version = "0.1"
		os = "windows"
		filetype = "executable"

	strings:
		$f1 = "advapi32.dll" nocase
		$c1 = "RegQueryValueExA"
		$c2 = "RegOpenKeyExA"
		$c3 = "RegCloseKey"
		$c4 = "RegSetValueExA"
		$c5 = "RegCreateKeyA"
		$c6 = "RegCloseKey"

	condition:
		$f1 and 1 of ($c*)
}
