rule iam_alt_iam_alt : Toolkit
{
	meta:
		description = "Auto-generated rule - file iam-alt.exe"
		author = "Florian Roth"
		reference = "http://www.coresecurity.com/corelabs-research/open-source-tools/pass-hash-toolkit"
		date = "2015-07-10"
		score = 80
		hash = "2ea662ef58142d9e340553ce50d95c1b7a405672acdfd476403a565bdd0cfb90"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "<cmd>. Create a new logon session and run a command with the specified credentials (e.g.: -r cmd.exe)" fullword ascii
		$s1 = "IAM-ALT v1.1 - by Hernan Ochoa (hochoa@coresecurity.com, hernan@gmail.com) - (c) 2007-2008 Core Security Technologies" fullword ascii
		$s2 = "This tool allows you to change the NTLM credentials of the current logon session" fullword ascii
		$s3 = "username:domainname:lmhash:nthash" fullword ascii
		$s4 = "Error in cmdline!. Bye!." fullword ascii
		$s5 = "Error: Cannot open LSASS.EXE!." fullword ascii
		$s6 = "nthash is too long!." fullword ascii
		$s7 = "LSASS HANDLE: %x" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <240KB and 2 of them
}
