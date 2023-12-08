import "pe"

rule Microcin_Sample_2
{
	meta:
		description = "Malware sample mentioned in Microcin technical report by Kaspersky"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/files/2017/09/Microcin_Technical-PDF_eng_final.pdf"
		date = "2017-09-26"
		hash1 = "8a7d04229722539f2480270851184d75b26c375a77b468d8cbad6dbdb0c99271"
		os = "windows"
		filetype = "executable"

	strings:
		$s2 = "[Pause]" fullword ascii
		$s7 = "IconCache_%02d%02d%02d%02d%02d" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and all of them )
}
