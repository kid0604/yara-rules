rule CobaltStrike_Unmodifed_Beacon
{
	meta:
		description = "Detects unmodified CobaltStrike beacon DLL"
		author = "yara@s3c.za.net"
		date = "2019-08-16"
		os = "windows"
		filetype = "executable"

	strings:
		$loader_export = "ReflectiveLoader"
		$exportname = "beacon.dll"

	condition:
		all of them
}
