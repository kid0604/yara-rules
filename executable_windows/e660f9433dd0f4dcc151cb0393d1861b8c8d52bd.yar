rule INDICATOR_KB_GoBuildID_Nemty
{
	meta:
		author = "ditekSHen"
		description = "Detects Golang Build IDs in known bad samples"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Go build ID: \"R6dvaUktgv2SjVXDoMdo/kKgwagwoLRC88DpIXAmx/eipNq7_PQCTCOhZ6Q74q/RHJkCaNdTbd6qgYiA-EC\"" ascii
		$s2 = "Go build ID: \"vsdndTwlj03gbEoDu06S/anJkXGh7N08537M0RMms/VG58d99axcdeD_z1JIko/tfDVbCdWUId-VX90kuT7\"" ascii
		$s3 = "Go build ID: \"FG9JEesXBQ04oNCv2bIS/MmjCdGa3ogU_6DIz6bZR/AjrqKBSezDfY1t7U9xr-/-06dIpZsukiVcN0PtOCb\"" ascii
		$s4 = "Go build ID: \"MJ8bS1emWrrlXiE_C61E/A6GaZzhLls_pFKMGfU1H/ZgswGQy_lzK-I4cZykwm/8JzjhV06jZosSa5Qih5O\"" ascii
		$s5 = "Go build ID: \"_vQalVQKn2O8kxxA4vVM/slXlklhnjEF5tawjlPzW/t26rDRURK6ii0MqU7gIx/MNq6vj_uM15RhjVC2QuX\"" ascii
		$s6 = "Go build ID: \"KWssFDTp6mq16xlI5c0t/mQLgof0oyp-eYKqNYUFL/Np8S71zE5W5_BsJCpjsj/hXpFDaVCtay2509R05fd\"" ascii

	condition:
		uint16(0)==0x5a4d and 1 of them
}
