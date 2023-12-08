rule gen_exploit_CVE_2017_10271_WebLogic : HIGHVOL
{
	meta:
		description = "Exploit for CVE-2017-10271 (Oracle WebLogic)"
		author = "John Lambert @JohnLaTwC"
		date = "2018-03-21"
		hash1 = "376c2bc11d4c366ad4f6fecffc0bea8b195e680b4c52a48d85a8d3f9fab01c95"
		hash2 = "7d5819a2ea62376e24f0dd3cf5466d97bbbf4f5f730eb9302307154b363967ea"
		hash3 = "864e9d8904941fae90ddd10eb03d998f85707dc2faff80cba2e365a64e830e1d/subfile"
		hash4 = "2a69e46094d0fef2b3ffcab73086c16a10b517f58e0c1f743ece4f246889962b"
		reference = "https://github.com/c0mmand3rOpSec/CVE-2017-10271, https://www.fireeye.com/blog/threat-research/2018/02/cve-2017-10271-used-to-deliver-cryptominers.html"
		os = "windows,linux"
		filetype = "script"

	strings:
		$s1 = "<soapenv:Header"
		$s2 = "java.beans.XMLDecoder"
		$s3 = "void" fullword
		$s4 = "index="
		$s5 = "/array>"
		$s6 = "\"start\""
		$s7 = "work:WorkContext" nocase

	condition:
		filesize <10KB and ( uint32(0)==0x616f733c or uint32(0)==0x54534f50) and all of ($s*)
}
