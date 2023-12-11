rule cerber4
{
	meta:
		description = "Detect the risk of Ransomware Cerber Rule 2"
		os = "windows"
		filetype = "executable"

	strings:
		$a = {8B 0D ?? ?? 43 00 51 8B 15 ?? ?? 43 00 52 E8 C9 04 00 00 83 C4 08 89 45 FC A1 ?? ?? 43 00 3B 05 ?? ?? 43 00 72 02}

	condition:
		1 of them
}
