import "pe"

rule IMPLANT_3_v3
{
	meta:
		description = "X-Agent/CHOPSTICK Implant by APT28"
		author = "US CERT"
		reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
		date = "2017-02-10"
		score = 85
		os = "windows"
		filetype = "executable"

	strings:
		$STR1 = ".?AVAgentKernel@@"
		$STR2 = ".?AVIAgentModule@@"
		$STR3 = "AgentKernel"

	condition:
		( uint16(0)==0x5A4D or uint16(0)==0xCFD0 or uint16(0)==0xC3D4 or uint32(0)==0x46445025 or uint32(1)==0x6674725C) and any of them
}
