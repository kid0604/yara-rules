private rule is_elf
{
	meta:
		description = "Detects ELF files based on file header"
		os = "linux"
		filetype = "executable"

	strings:
		$header = { 7F 45 4C 46 }

	condition:
		$header at 0
}
