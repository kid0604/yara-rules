import "pe"
import "hash"

rule Mirai_MIPS_MSB : MALW
{
	meta:
		description = "Mirai Botnet TR-069 Worm - MIPS MSB"
		author = "Felipe Molina / @felmoltor"
		date = "2016-12-04"
		version = "1.0"
		MD5 = "0eb51d584712485300ad8e8126773941"
		SHA1 = "18bce2f0107b5fab1b0b7c453e2a6b6505200cbd"
		ref1 = "http://www.theregister.co.uk/2016/11/28/router_flaw_exploited_in_massive_attack/"
		ref2 = "https://isc.sans.edu/forums/diary/Port+7547+SOAP+Remote+Code+Execution+Attack+Against+DSL+Modems/21759"
		ref3 = "https://krebsonsecurity.com/2016/11/new-mirai-worm-knocks-900k-germans-offline/"
		os = "linux"
		filetype = "executable"

	strings:
		$miname = "Myname--is:"
		$iptables1 = "busybox iptables -A INPUT -p tcp --destination-port 7547 -j DROP"
		$iptables2 = "busybox iptables -A INPUT -p tcp --destination-port 5555 -j DROP"
		$procnet = "/proc/net/tcp"

	condition:
		$miname and $iptables1 and $iptables2 and $procnet and hash.sha1(0, filesize )=="18bce2f0107b5fab1b0b7c453e2a6b6505200cbd"
}
