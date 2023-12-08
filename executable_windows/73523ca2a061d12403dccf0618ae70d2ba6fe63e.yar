import "pe"

rule APT_APT41_HIGHNOON_2
{
	meta:
		description = "Detects APT41 malware HIGHNOON"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html"
		date = "2019-08-07"
		hash1 = "79190925bd1c3fae65b0d11db40ac8e61fb9326ccfed9b7e09084b891089602d"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "H:\\RBDoor\\" ascii
		$s1 = "PlusDll.dll" fullword ascii
		$s2 = "ShutDownEvent.dll" fullword ascii
		$s3 = "\\svchost.exe" ascii

	condition:
		uint16(0)==0x5a4d and filesize <600KB and (pe.imphash()=="b70358b00dd0138566ac940d0da26a03" or pe.exports("DllMain_mem") or $x1 or 3 of them )
}
