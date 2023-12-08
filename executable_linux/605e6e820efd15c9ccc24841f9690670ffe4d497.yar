import "pe"

rule APT_Controller_Linux_REDFLARE_1
{
	meta:
		date_created = "2020-12-02"
		date_modified = "2020-12-02"
		md5 = "79259451ff47b864d71fb3f94b1774f3, 82773afa0860d668d7fe40e3f22b0f3e"
		rev = 1
		author = "FireEye"
		description = "Detects APT_Controller_Linux_REDFLARE_1 malware"
		os = "linux"
		filetype = "executable"

	strings:
		$1 = "/RedFlare/gorat_server"
		$2 = "RedFlare/sandals"
		$3 = "goratsvr.CommandResponse" fullword
		$4 = "goratsvr.CommandRequest" fullword

	condition:
		( uint32(0)==0x464c457f) and all of them
}
