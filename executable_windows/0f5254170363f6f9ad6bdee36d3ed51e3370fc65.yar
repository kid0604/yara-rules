rule Explosion_Generic_1
{
	meta:
		description = "Generic Rule for Explosion/Explosive Malware - Volatile Cedar APT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "not set"
		date = "2015/04/03"
		score = 70
		super_rule = 1
		hash0 = "d0f059ba21f06021579835a55220d1e822d1233f95879ea6f7cb9d301408c821"
		hash1 = "1952fa94b582e9af9dca596b5e51c585a78b8b1610639e3b878bbfa365e8e908"
		hash2 = "d8fdcdaad652c19f4f4676cd2f89ae834dbc19e2759a206044b18601875f2726"
		hash3 = "e2e6ed82703de21eb4c5885730ba3db42f3ddda8b94beb2ee0c3af61bc435747"
		hash4 = "03641e5632673615f23b2a8325d7355c4499a40f47b6ae094606a73c56e24ad0"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "autorun.exe" fullword
		$s1 = "User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; MSIE 6.0; Windows NT 5.1; .NET CL"
		$s2 = "%drp.exe" fullword
		$s3 = "%s_%s%d.exe" fullword
		$s4 = "open=autorun.exe" fullword
		$s5 = "http://www.microsoft.com/en-us/default.aspx" fullword
		$s10 = "error.renamefile" fullword
		$s12 = "insufficient lookahead" fullword
		$s13 = "%s %s|" fullword
		$s16 = ":\\autorun.exe" fullword

	condition:
		7 of them and uint16(0)==0x5A4D
}
