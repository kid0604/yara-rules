import "pe"

rule MALWARE_Win_CoinMiner03
{
	meta:
		author = "ditekSHen"
		description = "Detects coinmining malware"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "UnVzc2lhbiBTdGFuZGFyZCBUaW1l" wide
		$s2 = "/xmrig" wide
		$s3 = "/gminer" wide
		$s4 = "-o {0} -u {1} -p {2} -k --cpu-priority 0 --threads={3}" wide
		$s5 = "--algo ethash --server" wide
		$s6 = "--algo kawpow --server" wide
		$cnc1 = "/delonl.php?hwid=" fullword wide
		$cnc2 = "/gateonl.php?hwid=" fullword wide
		$cnc3 = "&cpuname=" fullword wide
		$cnc4 = "&gpuname=" fullword wide
		$cnc5 = "{0}/gate.php?hwid={1}&os={2}&cpu={3}&gpu={4}&dateinstall={5}&gpumem={6}" fullword wide
		$cnc6 = "/del.php?hwid=" fullword wide
		$f1 = "<StartGpuethGminer>b__" ascii
		$f2 = "<StartGpuetcGminer>b__" ascii
		$f3 = "<StartGpurvnGminer>b__" ascii

	condition:
		uint16(0)==0x5a4d and (3 of ($cnc*) or (2 of ($f*) and (1 of ($s*) or 1 of ($f*))) or all of ($f*) or 5 of ($s*))
}
