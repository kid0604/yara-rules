rule BlackTech_TSCookie_elf
{
	meta:
		description = "TSCookie ELF version"
		author = "JPCERT/CC Incident Response Group"
		hash = "698643b4c1b11ff227b3c821a0606025aaff390a46638aeb13ed8477c73f28cc"
		os = "linux"
		filetype = "executable"

	strings:
		$command = { 07 AC 00 72 }
		$senddata = { 0? BC 63 72 }
		$config = { C7 ?? ?? ?? 80 00 00 00 89 ?? ?? ?? C7 ?? ?? ?? 78 0B 00 00 }

	condition:
		(#senddata>=10 and $command) or $config
}
