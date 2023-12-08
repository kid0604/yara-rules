import "pe"

rule APT_Lazarus_Dropper_Jun18_1
{
	meta:
		description = "Detects Lazarus Group Dropper"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/DrunkBinary/status/1002587521073721346"
		date = "2018-06-01"
		hash1 = "086a50476f5ceee4b10871c1a8b0a794e96a337966382248a8289598b732bd47"
		hash2 = "9f2d4fd79d3c68270102c4c11f3e968c10610a2106cbf1298827f8efccdd70a9"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = /%s\\windows10-kb[0-9]{7}.exe/ fullword ascii
		$s2 = "EYEJIW" fullword ascii
		$s3 = "update" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <21000KB and (pe.imphash()=="fcac768eff9896d667a7c706d70712ce" or all of them )
}
