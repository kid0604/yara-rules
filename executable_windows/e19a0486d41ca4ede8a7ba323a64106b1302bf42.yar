rule RULE_ETERNALBLUE_GENERIC_SHELLCODE
{
	meta:
		description = "Detect the risk of Wannamine Rule 1"
		detail = "Detecta una shellcode genérica de EternalBlue, con payload variable"
		os = "windows"
		filetype = "executable"

	strings:
		$sc = { 31 c0 40 0f 84 ?? ?? ?? ?? 60 e8 00 00 00 00 5b e8 23 00 00 00 b9
      76 01 00 00 0f 32 8d 7b 39 39 }

	condition:
		all of them
}
