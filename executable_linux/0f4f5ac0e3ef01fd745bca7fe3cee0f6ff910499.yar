import "hash"

rule Hajime_MIPS : MALW
{
	meta:
		description = "Hajime Botnet - MIPS"
		author = "Joan Soriano / @joanbtl"
		date = "2017-05-01"
		version = "1.0"
		MD5 = "77122e0e6fcf18df9572d80c4eedd88d"
		SHA1 = "108ee460d4c11ea373b7bba92086dd8023c0654f"
		ref1 = "https://www.symantec.com/connect/blogs/hajime-worm-battles-mirai-control-internet-things/"
		ref2 = "https://security.rapiditynetworks.com/publications/2016-10-16/hajime.pdf"
		os = "linux"
		filetype = "executable"

	strings:
		$userpass = "%d (!=0),user/pass auth will not work, ignored.\n"
		$etcTZ = "/etc/TZ"
		$Mvrs = ",M4.1.0,M10.5.0"
		$bld = "%u.%u.%u.%u.in-addr.arpa"

	condition:
		$userpass and $etcTZ and $Mvrs and $bld and hash.sha1(0, filesize )=="108ee460d4c11ea373b7bba92086dd8023c0654f"
}
