rule CobaltStrike_MZ_Launcher
{
	meta:
		description = "Detects CobaltStrike MZ header ReflectiveLoader launcher"
		author = "yara@s3c.za.net"
		date = "2021-07-08"
		os = "windows"
		filetype = "executable"

	strings:
		$mz_launcher = { 4D 5A 41 52 55 48 89 E5 48 81 EC 20 00 00 00 48 8D 1D }

	condition:
		$mz_launcher
}
