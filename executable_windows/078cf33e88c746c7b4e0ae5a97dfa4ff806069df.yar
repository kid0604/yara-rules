import "pe"

rule CN_Portscan_alt_1 : APT
{
	meta:
		description = "CN Port Scanner"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2013-11-29"
		confidential = false
		score = 70
		os = "windows"
		filetype = "executable"

	strings:
		$s2 = "TCP 12.12.12.12"

	condition:
		uint16(0)==0x5A4D and $s2
}
