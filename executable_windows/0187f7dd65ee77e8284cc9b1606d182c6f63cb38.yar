import "pe"

rule APT_APT41_HIGHNOON_BIN
{
	meta:
		description = "Detects APT41 malware HIGHNOON.BIN"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html"
		date = "2019-08-07"
		score = 90
		hash1 = "490c3e4af829e85751a44d21b25de1781cfe4961afdef6bb5759d9451f530994"
		hash2 = "79190925bd1c3fae65b0d11db40ac8e61fb9326ccfed9b7e09084b891089602d"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "PlusDll.dll" fullword ascii
		$s2 = "\\Device\\PORTLESS_DeviceName" wide
		$s3 = "%s%s\\Security" fullword ascii
		$s4 = "%s\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" fullword ascii
		$s5 = "%s%s\\Enum" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <600KB and (pe.imphash()=="b70358b00dd0138566ac940d0da26a03" or 3 of them )
}
