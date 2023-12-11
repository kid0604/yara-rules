import "pe"

rule Linux_Portscan_Shark_1
{
	meta:
		description = "Detects Linux Port Scanner Shark"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Virustotal Research - see https://github.com/Neo23x0/Loki/issues/35"
		date = "2016-04-01"
		super_rule = 1
		hash1 = "4da0e535c36c0c52eaa66a5df6e070c52e7ddba13816efc3da5691ea2ec06c18"
		hash2 = "e395ca5f932419a4e6c598cae46f17b56eb7541929cdfb67ef347d9ec814dea3"
		os = "linux"
		filetype = "executable"

	strings:
		$s0 = "rm -rf scan.log session.txt" fullword ascii
		$s17 = "*** buffer overflow detected ***: %s terminated" fullword ascii
		$s18 = "*** stack smashing detected ***: %s terminated" fullword ascii

	condition:
		( uint16(0)==0x7362 and all of them )
}
