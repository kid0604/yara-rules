import "pe"

rule MAL_Visel_Sample_May18_1
{
	meta:
		description = "Detects Visel malware sample from Burning Umbrella report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://401trg.pw/burning-umbrella/"
		date = "2018-05-04"
		hash1 = "35db8e6a2eb5cf09cd98bf5d31f6356d0deaf4951b353fc513ce98918b91439c"
		os = "windows"
		filetype = "executable"

	strings:
		$s2 = "print32.dll" fullword ascii
		$s3 = "c:\\a\\b.txt" fullword ascii
		$s4 = "\\temp\\s%d.dat" wide

	condition:
		uint16(0)==0x5a4d and filesize <200KB and (pe.exports("szFile") or 2 of them )
}
