rule PoisonIvy_Sample_APT_3
{
	meta:
		description = "Detects a PoisonIvy Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 70
		reference = "VT Analysis"
		date = "2015-06-03"
		hash = "df3e1668ac20edecc12f2c1a873667ea1a6c3d6a"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "\\notepad.exe" ascii
		$s1 = "\\RasAuto.dll" ascii
		$s3 = "winlogon.exe" fullword ascii

	condition:
		uint16(0)==0x5a4d and all of them
}
