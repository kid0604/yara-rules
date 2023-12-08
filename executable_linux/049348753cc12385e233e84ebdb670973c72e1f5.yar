rule MAL_ELF_SALTWATER_Jun23_1
{
	meta:
		description = "Detects SALTWATER malware used in Barracuda ESG exploitations (CVE-2023-2868)"
		author = "Florian Roth"
		reference = "https://www.barracuda.com/company/legal/esg-vulnerability"
		date = "2023-06-07"
		score = 80
		hash1 = "601f44cc102ae5a113c0b5fe5d18350db8a24d780c0ff289880cc45de28e2b80"
		os = "linux"
		filetype = "executable"

	strings:
		$x1 = "libbindshell.so"
		$s1 = "ShellChannel"
		$s2 = "MyWriteAll"
		$s3 = "CheckRemoteIp"
		$s4 = "run_cmd"
		$s5 = "DownloadByProxyChannel"
		$s6 = "[-] error: popen failed"
		$s7 = "/home/product/code/config/ssl_engine_cert.pem"

	condition:
		uint16(0)==0x457f and filesize <6000KB and ((1 of ($x*) and 2 of them ) or 3 of them ) or all of them
}
