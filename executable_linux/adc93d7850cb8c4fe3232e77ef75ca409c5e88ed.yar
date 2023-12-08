rule APT_MAL_LNX_Hunting_Linux_WHIRLPOOL_1
{
	meta:
		description = "Hunting rule looking for strings observed in WHIRLPOOL samples."
		author = "Mandiant"
		date = "2023-06-15"
		score = 70
		reference = "https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally"
		hash = "177add288b289d43236d2dba33e65956"
		os = "linux"
		filetype = "executable"

	strings:
		$s1 = "error -1 exit" fullword
		$s2 = "create socket error: %s(error: %d)\n" fullword
		$s3 = "connect error: %s(error: %d)\n" fullword
		$s4 = {C7 00 20 32 3E 26 66 C7 40 04 31 00}
		$c1 = "plain_connect" fullword
		$c2 = "ssl_connect" fullword
		$c3 = "SSLShell.c" fullword

	condition:
		uint32(0)==0x464c457f and filesize <15MB and ( all of ($s*) or all of ($c*))
}
