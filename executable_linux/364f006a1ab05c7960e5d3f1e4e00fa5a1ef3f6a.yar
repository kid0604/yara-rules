import "hash"

rule Hajime_ARM5 : MALW
{
	meta:
		description = "Hajime Botnet - ARM5"
		author = "Joan Soriano / @joanbtl"
		date = "2017-05-01"
		version = "1.0"
		MD5 = "d8821a03b9dc484144285d9051e0b2d3"
		SHA1 = "89ec638b95b289dbce0535b4a2c5aad90c169d06"
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
		$userpass and $etcTZ and $Mvrs and $bld and hash.sha1(0, filesize )=="89ec638b95b289dbce0535b4a2c5aad90c169d06"
}
