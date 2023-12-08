import "pe"

rule Microcin_Sample_6
{
	meta:
		description = "Malware sample mentioned in Microcin technical report by Kaspersky"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/files/2017/09/Microcin_Technical-PDF_eng_final.pdf"
		date = "2017-09-26"
		hash1 = "cbd43e70dc55e94140099722d7b91b07a3997722d4a539ecc4015f37ea14a26e"
		hash2 = "871ab24fd6ae15783dd9df5010d794b6121c4316b11f30a55f23ba37eef4b87a"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "** ERROR ** %s: %s" fullword ascii
		$s2 = "TEMPDATA" fullword wide
		$s3 = "Bruntime error " fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <600KB and all of them )
}
