rule regshell
{
	meta:
		description = "Webshells Auto-generated - file regshell.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "db2fdc821ca6091bab3ebd0d8bc46ded"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "Changes the base hive to HKEY_CURRENT_USER."
		$s4 = "Displays a list of values and sub-keys in a registry Hive."
		$s5 = "Enter a menu selection number (1 - 3) or 99 to Exit: "

	condition:
		all of them
}
