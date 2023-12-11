import "hash"
import "pe"

rule dragos_crashoverride_hashes
{
	meta:
		description = "CRASHOVERRIDE Malware Hashes"
		author = "Dragos Inc"
		reference = "https://dragos.com/blog/crashoverride/CrashOverride-01.pdf"
		os = "windows"
		filetype = "executable"

	condition:
		filesize <1MB and hash.sha1(0, filesize )=="f6c21f8189ced6ae150f9ef2e82a3a57843b587d" or hash.sha1(0, filesize )=="cccce62996d578b984984426a024d9b250237533" or hash.sha1(0, filesize )=="8e39eca1e48240c01ee570631ae8f0c9a9637187" or hash.sha1(0, filesize )=="2cb8230281b86fa944d3043ae906016c8b5984d9" or hash.sha1(0, filesize )=="79ca89711cdaedb16b0ccccfdcfbd6aa7e57120a" or hash.sha1(0, filesize )=="94488f214b165512d2fc0438a581f5c9e3bd4d4c" or hash.sha1(0, filesize )=="5a5fafbc3fec8d36fd57b075ebf34119ba3bff04" or hash.sha1(0, filesize )=="b92149f046f00bb69de329b8457d32c24726ee00" or hash.sha1(0, filesize )=="b335163e6eb854df5e08e85026b2c3518891eda8"
}
