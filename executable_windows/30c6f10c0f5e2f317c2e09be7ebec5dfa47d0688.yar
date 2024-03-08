rule PikExport
{
	meta:
		author = "kevoreilly"
		description = "Pikabot export selection"
		cape_options = "export=$export"
		hash = "238dcc5611ed9066b63d2d0109c9b623f54f8d7b61d5f9de59694cfc60a4e646"
		os = "windows"
		filetype = "executable"

	strings:
		$export = {55 8B EC 83 EC ?? C6 45 [2] C6 45 [2] C6 45 [2] C6 45 [2] C6 45}
		$pe = {B8 08 00 00 00 6B C8 00 8B 55 ?? 8B 45 ?? 03 44 0A 78 89 45 ?? 8B 4D ?? 8B 51 18 89 55 E8 C7 45 F8 00 00 00 00}

	condition:
		uint16(0)==0x5A4D and all of them
}
