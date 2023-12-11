import "hash"

rule Hajime_SH4 : MALW
{
	meta:
		description = "Hajime Botnet - SH4"
		author = "Joan Soriano / @joanbtl"
		date = "2017-05-01"
		version = "1.0"
		MD5 = "6f39d7311091166a285fb0654b454761"
		SHA1 = "3ed95ead04e59a2833538541978b79a9a8cb5290"
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
		$userpass and $etcTZ and $Mvrs and $bld and hash.sha1(0, filesize )=="3ed95ead04e59a2833538541978b79a9a8cb5290"
}
