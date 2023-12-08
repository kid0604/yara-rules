import "pe"

rule APT_APT41_RevokedCert_Aug19_1
{
	meta:
		description = "Detects revoked certificates used by APT41 group"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html"
		date = "2019-08-07"
		score = 60
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].serial=="0b:72:79:06:8b:eb:15:ff:e8:06:0d:2c:56:15:3c:35" or pe.signatures[i].serial=="63:66:a9:ac:97:df:4d:e1:73:66:94:3c:9b:29:1a:aa" or pe.signatures[i].serial=="01:00:00:00:00:01:30:73:85:f7:02" or pe.signatures[i].serial=="14:0d:2c:51:5e:8e:e9:73:9b:b5:f1:b2:63:7d:c4:78" or pe.signatures[i].serial=="7b:d5:58:18:c5:97:1b:63:dc:45:cf:57:cb:eb:95:0b" or pe.signatures[i].serial=="53:0c:e1:4c:81:f3:62:10:a1:68:2a:ff:17:9e:25:80" or pe.signatures[i].serial=="54:c6:c1:40:6f:b4:ac:b5:d2:06:74:e9:93:92:c6:3e" or pe.signatures[i].serial=="fd:f2:83:7d:ac:12:b7:bb:30:ad:05:8f:99:9e:cf:00" or pe.signatures[i].serial=="18:63:79:57:5a:31:46:e2:6b:ef:c9:0a:58:0d:1b:d2" or pe.signatures[i].serial=="5c:2f:97:a3:1a:bc:32:b0:8c:ac:01:00:59:8f:32:f6" or pe.signatures[i].serial=="4c:0b:2e:9d:2e:f9:09:d1:52:70:d4:dd:7f:a5:a4:a5" or pe.signatures[i].serial=="58:01:5a:cd:50:1f:c9:c3:44:26:4e:ac:e2:ce:57:30" or pe.signatures[i].serial=="47:6b:f2:4a:4b:1e:9f:4b:c2:a6:1b:15:21:15:e1:fe" or pe.signatures[i].serial=="30:d3:c1:67:26:5b:52:0c:b8:7f:25:84:4f:95:cb:04" or pe.signatures[i].serial=="1e:52:bb:f5:c9:0e:c1:64:d0:5b:e0:e4:16:61:52:5f" or pe.signatures[i].serial=="25:f8:78:22:de:56:d3:98:21:59:28:73:ea:09:ca:37" or pe.signatures[i].serial=="67:24:34:0d:db:c7:25:2f:7f:b7:14:b8:12:a5:c0:4d")
}
