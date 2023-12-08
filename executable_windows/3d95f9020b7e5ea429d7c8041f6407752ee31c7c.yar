import "pe"

rule modifiedHACKSTOPv111f
{
	meta:
		author = "malware-lu"
		description = "Detects modified HACKSTOP v1.11f malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 52 B4 30 CD 21 52 FA ?? FB 3D [2] EB ?? CD 20 0E 1F B4 09 E8 }

	condition:
		$a0 at pe.entry_point
}
