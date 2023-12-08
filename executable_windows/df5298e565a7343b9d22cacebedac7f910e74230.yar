rule _iissample_nesscan_twwwscan
{
	meta:
		description = "Disclosed hacktool set (old stuff) - from files iissample.exe, nesscan.exe, twwwscan.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		super_rule = 1
		hash0 = "7f20962bbc6890bf48ee81de85d7d76a8464b862"
		hash1 = "c0b1a2196e82eea4ca8b8c25c57ec88e4478c25b"
		hash2 = "548f0d71ef6ffcc00c0b44367ec4b3bb0671d92f"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "Connecting HTTP Port - Result: " fullword
		$s1 = "No space for command line argument vector" fullword
		$s3 = "Microsoft(July/1999~) http://www.microsoft.com/technet/security/current.asp" fullword
		$s5 = "No space for copy of command line" fullword
		$s7 = "-  Windows NT,2000 Patch Method  - " fullword
		$s8 = "scanf : floating point formats not linked" fullword
		$s12 = "hrdir_b.c: LoadLibrary != mmdll borlndmm failed" fullword
		$s13 = "!\"what?\"" fullword
		$s14 = "%s Port %d Closed" fullword
		$s16 = "printf : floating point formats not linked" fullword
		$s17 = "xxtype.cpp" fullword

	condition:
		all of them
}
