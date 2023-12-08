import "pe"

rule Slingshot_APT_Malware_4
{
	meta:
		description = "Detects malware from Slingshot APT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/apt-slingshot/84312/"
		date = "2018-03-09"
		hash1 = "38c4f5320b03cbaf5c14997ea321507730a8c16906e5906cbf458139c91d5945"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "Ss -a 4104 -s 257092 -o 8 -l 406016 -r 4096 -z 315440" fullword wide
		$s1 = "Slingshot" fullword ascii
		$s2 = "\\\\?\\e:\\$Recycle.Bin\\" wide
		$s3 = "LineRecs.reloc" fullword ascii
		$s4 = "EXITGNG" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and ($x1 or 2 of them )
}
